# frozen_string_literal: true

require "base64"
require "digest"
require "ipaddr"
require "json"
require "net/http"
require "openssl"
require "resolv"
require "uri"

require_relative "machine_client"

module Atlas
  # Web Bot Auth: verify that a request comes from the bot it says it does. A bot signs its requests with
  # an Ed25519 key (HTTP Message Signatures, RFC 9421, +tag="web-bot-auth"+) and publishes the key in a
  # directory at +<Signature-Agent>/.well-known/http-message-signatures-directory+. {WebBotAuth::Verifier}
  # checks the signature, the time window and the signed components, fetches the directory safely and
  # decides against your allow and block lists.
  #
  #   verifier = Atlas::WebBotAuth::Verifier.new(allow: [{ directory: "https://bot.example.com", name: "ExampleBot" }])
  #   decision = verifier.verify(method: request.request_method, url: request.url, headers: request.headers)
  #   decision.tier      # => "allowed" | "blocked" | "verified" | "unverified"
  module WebBotAuth
    TAG = "web-bot-auth"
    DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
    DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"
    DEFAULT_SKEW_SECONDS = 30
    DEFAULT_MAX_LIFETIME_SECONDS = 3600
    DIRECTORY_MAX_BYTES = 64 * 1024

    # What {verify_request} found. +reason+ is set on a failure (see FAILURES).
    Result = Struct.new(:signed, :verified, :reason, :directory, :key_id, :label, :created, :expires, :nonce, keyword_init: true) do
      def signed? = signed == true
      def verified? = verified == true
    end

    # Your decision: +tier+ is +"allowed"+, +"blocked"+, +"verified"+ (a real bot you have no rule for) or
    # +"unverified"+; +decision+ is +:allow+, +:block+ or +:unknown+.
    Decision = Struct.new(:verified, :agent, :tier, :decision, :reason, keyword_init: true) do
      def verified? = verified == true
    end

    FAILURES = %i[no_signature no_web_bot_auth_signature malformed missing_signature_agent bad_signature_agent bad_params
                  unsupported_algorithm unsupported_component component_missing components_not_covered bad_request
                  not_yet_valid expired lifetime_too_long directory_unavailable key_not_found bad_signature replayed].freeze

    KEY_RE = /\A[a-z*][a-z0-9_.*-]*\z/
    TOKEN_CHARS = %r{[A-Za-z0-9:/!#$%&'*+\-.^_`|~]}
    DERIVED = %w[@method @authority @path @target-uri @scheme @query @request-target].freeze
    ED25519_SPKI_PREFIX = ["302a300506032b6570032100"].pack("H*")

    module_function

    # ---- encoding and keys ----

    def b64u(bytes) = Base64.urlsafe_encode64(bytes, padding: false)

    def b64u_decode(input)
      return nil unless input.match?(/\A[A-Za-z0-9_-]*\z/)

      base64_decode(input.tr("-_", "+/"))
    end

    def base64_decode(input)
      return nil unless input.match?(%r{\A[A-Za-z0-9+/]*={0,2}\z})

      Base64.decode64(input + ("=" * ((4 - (input.length % 4)) % 4)))
    end

    # The RFC 7638 thumbprint of an Ed25519 JWK: the +keyid+ a Web Bot Auth signature carries.
    def jwk_thumbprint(jwk)
      b64u(Digest::SHA256.digest(%({"crv":"Ed25519","kty":"OKP","x":"#{fetch(jwk, 'x')}"})))
    end

    # The 32 key bytes of an Ed25519 JWK, or nil when it is not one.
    def jwk_bytes(jwk)
      return nil unless jwk.is_a?(Hash) && fetch(jwk, "kty") == "OKP" && fetch(jwk, "crv") == "Ed25519" && fetch(jwk, "x").is_a?(String)

      bytes = b64u_decode(fetch(jwk, "x"))
      bytes && bytes.bytesize == 32 ? bytes : nil
    end

    # The Ed25519 keys of a directory document (at most 20).
    def parse_directory(doc)
      keys = doc.is_a?(Hash) ? fetch(doc, "keys") : nil
      keys.is_a?(Array) ? keys.select { |k| jwk_bytes(k) }.first(20) : []
    end

    def fetch(hash, key) = hash.key?(key) ? hash[key] : hash[key.to_sym]

    # ---- structured fields (the subset RFC 9421 headers use) ----

    def split_top(str, sep)
      out = []
      depth = 0
      quoted = false
      start = 0
      i = 0
      while i < str.length
        c = str[i]
        if quoted
          if c == "\\" then i += 1
          elsif c == '"' then quoted = false
          end
        elsif c == '"' then quoted = true
        elsif c == "(" then depth += 1
        elsif c == ")" then depth -= 1
        elsif c == sep && depth.zero?
          out << str[start...i]
          start = i + 1
        end
        i += 1
      end
      out << str[start..]
      out.map(&:strip).reject(&:empty?)
    end

    # @return [Array(String, Integer), nil] the string value and the index after it.
    def read_string(str, i)
      return nil unless str[i] == '"'

      out = +""
      j = i + 1
      while j < str.length
        c = str[j]
        if c == "\\"
          n = str[j + 1]
          return nil unless ['"', "\\"].include?(n)

          out << n
          j += 1
        elsif c == '"'
          return [out, j + 1]
        elsif c.ord < 0x20 || c.ord > 0x7e
          return nil
        else
          out << c
        end
        j += 1
      end
      nil
    end

    def parse_params(text)
      out = {}
      i = 0
      while i < text.length
        return nil unless text[i] == ";"

        i += 1
        key = +""
        key << text[i].tap { i += 1 } while i < text.length && text[i].match?(/[a-z0-9_.*-]/)
        return nil unless key.match?(KEY_RE)

        unless text[i] == "="
          out[key] = true
          next
        end
        i += 1
        c = text[i]
        if c == '"'
          str = read_string(text, i) or return nil
          out[key], i = str
        elsif c == ":"
          close = text.index(":", i + 1) or return nil
          bytes = base64_decode(text[(i + 1)...close]) or return nil
          out[key] = bytes
          i = close + 1
        elsif c == "?"
          b = text[i, 2]
          return nil unless %w[?0 ?1].include?(b)

          out[key] = b == "?1"
          i += 2
        elsif c && c.match?(/[-0-9]/)
          n = +""
          n << text[i].tap { i += 1 } while i < text.length && text[i].match?(/[-0-9.]/)
          return nil unless n.match?(/\A-?\d{1,15}(\.\d{1,3})?\z/)

          out[key] = n.include?(".") ? n.to_f : n.to_i
        elsif c && c.match?(/[A-Za-z*]/)
          t = +""
          t << text[i].tap { i += 1 } while i < text.length && text[i].match?(TOKEN_CHARS)
          out[key] = t
        else
          return nil
        end
      end
      out
    end

    Component = Struct.new(:name, :params, keyword_init: true)

    # @return [Array<Hash>, nil] +[{ label:, components: [Component], params:, raw: }]+
    def parse_signature_input(header)
      out = []
      split_top(header, ",").each do |member|
        eq = member.index("=")
        return nil if eq.nil? || eq <= 0

        label = member[0...eq].strip
        raw = member[(eq + 1)..].strip
        return nil unless label.match?(KEY_RE) && raw[0] == "("

        close = nil
        quoted = false
        k = 1
        while k < raw.length
          c = raw[k]
          if quoted
            if c == "\\" then k += 1
            elsif c == '"' then quoted = false
            end
          elsif c == '"' then quoted = true
          elsif c == ")"
            close = k
            break
          end
          k += 1
        end
        return nil if close.nil?

        components = []
        inner = raw[1...close]
        i = 0
        while i < inner.length
          if inner[i] == " "
            i += 1
            next
          end
          str = read_string(inner, i) or return nil
          name, i = str
          ptext = +""
          while i < inner.length && inner[i] != " "
            if inner[i] == '"'
              q = read_string(inner, i) or return nil
              ptext << inner[i...q[1]]
              i = q[1]
            else
              ptext << inner[i]
              i += 1
            end
          end
          params = parse_params(ptext) or return nil
          components << Component.new(name: name, params: params)
        end
        params = parse_params(raw[(close + 1)..]) or return nil
        out << { label: label, components: components, params: params, raw: raw }
      end
      out.empty? ? nil : out
    end

    # @return [Hash{String=>String}, nil] label => raw signature bytes
    def parse_signature_header(header)
      out = {}
      split_top(header, ",").each do |member|
        m = /\A([a-z*][a-z0-9_.*-]*)=:([A-Za-z0-9+\/=]*):\z/.match(member) or return nil
        bytes = base64_decode(m[2]) or return nil
        out[m[1]] = bytes
      end
      out.empty? ? nil : out
    end

    # The directory a +Signature-Agent+ header names, normalised, or nil.
    def parse_signature_agent(value, label = nil)
      v = value.strip
      return nil if v.empty?

      if v.match?(/\A[a-z*][a-z0-9_.*-]*=/)
        members = split_top(v, ",")
        pick = members.find { |m| label && m.start_with?("#{label}=") } || members.first
        v = pick[(pick.index("=") + 1)..].strip
      end
      if v.start_with?('"')
        str = read_string(v, 0)
        return nil if str.nil? || str[1] != v.length

        v = str[0]
      end
      normalize_directory(v)
    end

    # +https://host/path+ with no credentials, query or fragment and no trailing slash; nil otherwise.
    def normalize_directory(input)
      s = input.to_s.strip
      return nil if s.empty?

      s = "https://#{s}" unless s.match?(%r{\A[a-z][a-z0-9+.-]*://}i)
      u = URI.parse(s)
      return nil unless u.scheme == "https" && u.userinfo.nil? && u.query.nil? && u.fragment.nil? && !u.host.to_s.empty?

      origin = "https://#{u.host.downcase}#{u.port == 443 ? '' : ":#{u.port}"}"
      "#{origin}#{u.path.sub(%r{/+\z}, '')}"
    rescue URI::InvalidURIError
      nil
    end

    def directory_url_for(directory) = "#{directory}#{DIRECTORY_PATH}"

    # ---- the signature base (RFC 9421 2.5) ----

    # The value of header +name+ in a Hash of headers (String or Array values; several are joined with ", ").
    def header_value(headers, name)
      return headers.get(name.downcase)&.strip if headers.respond_to?(:get) && !headers.is_a?(Hash)

      lower = name.downcase
      parts = []
      headers.each do |k, v|
        next unless k.to_s.downcase == lower && !v.nil?

        Array(v).each { |item| parts << item.to_s.strip }
      end
      parts.empty? ? nil : parts.join(", ")
    end

    def sf_string(v) = "\"#{v.gsub(/[\\"]/) { |m| "\\#{m}" }}\""

    # RFC 9421 component identifier: +"name";param=value+.
    def serialize_component_id(c)
      name = c.is_a?(Component) ? c.name : c.is_a?(Hash) ? (c[:name] || c["name"]) : c.to_s
      params = c.is_a?(Component) ? c.params : c.is_a?(Hash) ? (c[:params] || c["params"] || {}) : {}
      out = +sf_string(name)
      (params || {}).each do |k, v|
        out << case v
               when true then ";#{k}"
               when false then ";#{k}=?0"
               when String then v.encoding == Encoding::BINARY && !v.ascii_only? ? ";#{k}=:#{Base64.strict_encode64(v)}:" : ";#{k}=#{sf_string(v)}"
               else ";#{k}=#{v}"
               end
      end
      out
    end

    def percent_encode(v) = URI.encode_www_form_component(v).gsub("+", "%20").gsub(/[!'()*]/) { |c| format("%%%02X", c.ord) }

    def sf_bare_item(text, i)
      c = text[i]
      if c == '"'
        str = read_string(text, i) or return nil
        [text[i...str[1]], str[1]]
      elsif c == ":"
        close = text.index(":", i + 1)
        return nil if close.nil? || base64_decode(text[(i + 1)...close]).nil?

        [text[i..close], close + 1]
      elsif c == "?"
        b = text[i, 2]
        %w[?0 ?1].include?(b) ? [b, i + 2] : nil
      elsif c && c.match?(/[-0-9]/)
        m = /\A-?\d{1,15}(\.\d{1,3})?/.match(text[i..]) or return nil
        return [m[0], i + m[0].length] if m[1].nil?

        fixed = format("%.3f", m[0].to_f).sub(/0+\z/, "")
        [fixed.end_with?(".") ? "#{fixed}0" : fixed, i + m[0].length]
      elsif c && c.match?(/[A-Za-z*]/)
        j = i
        j += 1 while j < text.length && text[j].match?(TOKEN_CHARS)
        [text[i...j], j]
      end
    end

    def sf_params(text, i)
      out = +""
      loop do
        j = i
        j += 1 while text[j] == " " || text[j] == "\t"
        return [out, i] unless text[j] == ";"

        j += 1
        j += 1 while text[j] == " "
        key = /\A[a-z*][a-z0-9_.*-]*/.match(text[j..])&.to_s
        return nil unless key

        j += key.length
        out << ";#{key}"
        if text[j] == "="
          v = sf_bare_item(text, j + 1) or return nil
          out << "=#{v[0]}"
          j = v[1]
        end
        i = j
      end
    end

    def sf_item(text)
      t = text.strip
      if t[0] == "("
        depth = 0
        quoted = false
        close = nil
        k = 0
        while k < t.length
          ch = t[k]
          if quoted
            if ch == "\\" then k += 1
            elsif ch == '"' then quoted = false
            end
          elsif ch == '"' then quoted = true
          elsif ch == "(" then depth += 1
          elsif ch == ")"
            depth -= 1
            if depth.zero?
              close = k
              break
            end
          end
          k += 1
        end
        return nil if close.nil?

        members = []
        split_top(t[1...close].gsub(/\s+/, " "), " ").each do |m|
          canon = sf_item(m) or return nil
          members << canon
        end
        body = ["(#{members.join(' ')})", close + 1]
      else
        body = sf_bare_item(t, 0)
      end
      return nil unless body

      params = sf_params(t, body[1])
      return nil if params.nil? || !t[params[1]..].to_s.strip.empty?

      body[0] + params[0]
    end

    def sf_dictionary(text)
      out = []
      split_top(text, ",").each do |member|
        key = /\A[a-z*][a-z0-9_.*-]*/.match(member)&.to_s or return nil
        rest = member[key.length..]
        value = rest.start_with?("=") ? sf_item(rest[1..]) : sf_item("?1#{rest}")
        return nil if value.nil?

        out << [key, value]
      end
      out.empty? ? nil : out
    end

    # Canonical structured-field serialization of a header value, for the +sf+ parameter.
    def sf_serialize(text)
      members = split_top(text, ",")
      if !members.empty? && members.all? { |m| m.match?(/\A[a-z*][a-z0-9_.*-]*(=|;|\z)/) } && members.any? { |m| m.match?(/\A[a-z*][a-z0-9_.*-]*=/) }
        dict = sf_dictionary(text) or return nil
        return dict.map { |k, v| v == "?1" ? k : v.start_with?("?1;") ? "#{k}#{v[2..]}" : "#{k}=#{v}" }.join(", ")
      end
      items = members.map { |m| sf_item(m) }
      items.empty? || items.any?(&:nil?) ? nil : items.join(", ")
    end

    def uri_parts(url)
      u = URI.parse(url)
      raise URI::InvalidURIError, "no host" if u.host.nil? || u.scheme.nil?

      u
    end

    def component_value(name, params, headers, method, uri)
      keys = params.keys
      if name == "@query-param"
        return nil unless keys == ["name"] && params["name"].is_a?(String)

        found = URI.decode_www_form(uri.query.to_s).select { |k, _| k == params["name"] }
        return found.length == 1 ? percent_encode(found[0][1]) : nil
      end
      if name.start_with?("@")
        return nil unless keys.empty?

        path = uri.path.to_s.empty? ? "/" : uri.path
        authority = "#{uri.host.downcase}#{uri.port == uri.default_port ? '' : ":#{uri.port}"}"
        search = uri.query ? "?#{uri.query}" : ""
        return case name
               when "@method" then method.to_s.upcase
               when "@authority" then authority
               when "@path" then path
               when "@target-uri" then "#{uri.scheme.downcase}://#{authority}#{path}#{search}"
               when "@scheme" then uri.scheme.downcase
               when "@query" then search.empty? ? "?" : search
               when "@request-target" then "#{path}#{search}"
               end
      end
      raw = header_value(headers, name)
      return nil if raw.nil?
      return raw if keys.empty?
      return nil unless keys.length == 1

      if params["sf"] == true
        sf_serialize(raw)
      elsif params["key"].is_a?(String)
        sf_dictionary(raw)&.find { |k, _| k == params["key"] }&.last
      elsif params["bs"] == true
        ":#{Base64.strict_encode64(raw)}:"
      end
    end

    # The RFC 9421 signature base for +components+, ending in the +@signature-params+ line.
    # @return [Hash] +{ base: }+ or +{ error: :unsupported_component | :component_missing | :bad_request }+
    def build_signature_base(method:, url:, headers:, components:, signature_params:)
      uri = begin
        uri_parts(url)
      rescue URI::InvalidURIError
        return { error: :bad_request }
      end
      seen = []
      lines = []
      components.each do |entry|
        c = entry.is_a?(Component) ? entry : entry.is_a?(Hash) ? Component.new(name: entry[:name] || entry["name"], params: entry[:params] || entry["params"] || {}) : Component.new(name: entry.to_s, params: {})
        c.params ||= {}
        return { error: :unsupported_component } if c.name != c.name.downcase
        return { error: :unsupported_component } if c.name.start_with?("@") && !DERIVED.include?(c.name) && c.name != "@query-param"

        id = serialize_component_id(c)
        return { error: :unsupported_component } if seen.include?(id)

        seen << id
        return { error: :unsupported_component } unless c.params.keys.all? { |k| %w[sf key bs name].include?(k) }
        # A derived component takes no header parameters (only @query-param takes `name`).
        return { error: :unsupported_component } if c.name.start_with?("@") && c.name != "@query-param" && !c.params.empty?

        v = component_value(c.name, c.params, headers, method, uri)
        return { error: :component_missing } if v.nil? || v.match?(/[\r\n]/)

        lines << "#{id}: #{v}"
      end
      lines << "\"@signature-params\": #{signature_params}"
      { base: lines.join("\n") }
    end

    # ---- verification ----

    def failure(reason, extra = {})
      Result.new(signed: true, verified: false, reason: reason, **extra)
    end

    def ed25519_public_key(bytes)
      OpenSSL::PKey.read(ED25519_SPKI_PREFIX + bytes)
    end

    # Verify the Web Bot Auth signature on a request.
    #
    # @param get_keys [#call] +(directory_url, refresh:) -> Array<Hash> | nil+: the directory's JWKs ({DirectoryCache#get_keys}).
    # @param now [Time, Numeric, nil] the current time (epoch seconds when numeric).
    # @param claim_nonce [#call, nil] +(key, expires_at_ms) -> Boolean+ (false = replayed).
    # @return [Atlas::WebBotAuth::Result]
    def verify_request(method:, url:, headers:, get_keys:, now: nil, skew_seconds: DEFAULT_SKEW_SECONDS,
                       max_lifetime_seconds: DEFAULT_MAX_LIFETIME_SECONDS, claim_nonce: nil)
      input_header = header_value(headers, "signature-input")
      sig_header = header_value(headers, "signature")
      return Result.new(signed: false, verified: false, reason: :no_signature) if input_header.nil? || sig_header.nil?

      inputs = parse_signature_input(input_header)
      sigs = parse_signature_header(sig_header)
      return failure(:malformed) if inputs.nil? || sigs.nil?

      input = inputs.find { |i| i[:params]["tag"] == TAG && sigs.key?(i[:label]) }
      return failure(:no_web_bot_auth_signature) unless input

      signature = sigs[input[:label]]
      p = input[:params]
      created = p["created"]
      expires = p["expires"]
      key_id = p["keyid"]
      nonce = p["nonce"]
      unless created.is_a?(Integer) && expires.is_a?(Integer) && key_id.is_a?(String) && !key_id.empty? && key_id.length <= 128 &&
             (nonce.nil? || (nonce.is_a?(String) && nonce.length <= 512))
        return failure(:bad_params, label: input[:label])
      end

      base = { label: input[:label], key_id: key_id, created: created, expires: expires }
      return failure(:unsupported_algorithm, **base) if p.key?("alg") && p["alg"] != "ed25519"

      now_sec = (now.nil? ? Time.now : now).to_i
      return failure(:bad_params, **base) if expires <= created
      return failure(:lifetime_too_long, **base) if expires - created > max_lifetime_seconds
      return failure(:not_yet_valid, **base) if created > now_sec + skew_seconds
      return failure(:expired, **base) if expires < now_sec - skew_seconds

      # Coverage: the signature must bind the host, and the directory claim it relies on.
      names = input[:components].map(&:name)
      agent_header = header_value(headers, "signature-agent")
      return failure(:missing_signature_agent, **base) if agent_header.nil?

      agent_component = input[:components].find { |c| c.name == "signature-agent" }
      return failure(:components_not_covered, **base) if !names.include?("@authority") || agent_component.nil?

      # Covered as a dictionary member (`;key="m"`): the directory must come from that member, or an uncovered one could be swapped in.
      agent_key = agent_component.params["key"].is_a?(String) ? agent_component.params["key"] : nil
      return failure(:bad_signature_agent, **base) if agent_key && split_top(agent_header, ",").none? { |m| m.start_with?("#{agent_key}=") }

      directory = parse_signature_agent(agent_header, agent_key || input[:label])
      return failure(:bad_signature_agent, **base) unless directory

      with_dir = base.merge(directory: directory)
      built = build_signature_base(method: method, url: url, headers: headers, components: input[:components], signature_params: input[:raw])
      return failure(built[:error], **with_dir) if built[:error]

      dir_url = directory_url_for(directory)
      find = ->(keys) { keys&.find { |k| jwk_thumbprint(k) == key_id } }
      keys = get_keys.call(dir_url, refresh: false)
      jwk = find.call(keys)
      unless jwk
        keys = get_keys.call(dir_url, refresh: true)
        jwk = find.call(keys)
      end
      return failure(keys.nil? ? :directory_unavailable : :key_not_found, **with_dir) unless jwk

      pub = jwk_bytes(jwk)
      ok = begin
        !pub.nil? && signature.bytesize == 64 && ed25519_public_key(pub).verify(nil, signature, built[:base])
      rescue StandardError
        false
      end
      return failure(:bad_signature, **with_dir) unless ok

      if claim_nonce && nonce.is_a?(String) && !claim_nonce.call("#{directory}|#{key_id}|#{nonce}", (expires * 1000) + (skew_seconds * 1000))
        return failure(:replayed, **with_dir)
      end

      Result.new(signed: true, verified: true, nonce: nonce.is_a?(String) ? nonce : nil, **with_dir)
    end

    # Sign a request the way a bot does (also handy in tests).
    # @param private_key [String] a PKCS#8 PEM, or the 32-byte Ed25519 seed.
    # @return [Hash{String=>String}] the +signature-agent+, +signature-input+ and +signature+ headers to send.
    def sign_request(method:, url:, signature_agent:, private_key:, created:, expires:, headers: {}, nonce: nil, label: "sig1", components: nil)
      components ||= ["@authority", "signature-agent"]
      key = private_key.bytesize == 32 && !private_key.include?("BEGIN") ? Atlas::Ed25519Raw.from_seed(private_key) : OpenSSL::PKey.read(private_key)
      key_id = jwk_thumbprint("x" => b64u(Atlas::Ed25519Raw.public_bytes(key)))
      agent_header = "\"#{signature_agent}\""
      comps = components.map { |c| c.is_a?(String) ? Component.new(name: c, params: {}) : (c.is_a?(Component) ? c : Component.new(name: c[:name], params: c[:params] || {})) }
      params = "(#{comps.map { |c| serialize_component_id(c) }.join(' ')});created=#{created};keyid=\"#{key_id}\";alg=\"ed25519\";expires=#{expires}" \
               "#{nonce ? ";nonce=\"#{nonce}\"" : ''};tag=\"#{TAG}\""
      all_headers = headers.merge("signature-agent" => agent_header)
      built = build_signature_base(method: method, url: url, headers: all_headers, components: comps, signature_params: params)
      raise ArgumentError, "Cannot sign: #{built[:error]}." if built[:error]

      { "signature-agent" => agent_header, "signature-input" => "#{label}=#{params}",
        "signature" => "#{label}=:#{Base64.strict_encode64(key.sign(nil, built[:base]))}:" }
    end

    # Decide what a verification result means for you. +allow+ / +block+ are lists of +{ directory:, name: }+.
    def decide(result, allow: [], block: [])
      unless result.verified? && result.directory && result.key_id
        return Decision.new(verified: false, agent: nil, tier: "unverified", decision: :unknown, reason: result.reason)
      end

      match = ->(list) { Array(list).find { |e| normalize_directory(fetch(e, "directory")) == result.directory } }
      blocked = match.call(block)
      allowed = blocked ? nil : match.call(allow)
      entry = blocked || allowed
      name = entry && fetch(entry, "name").to_s.strip
      name = URI.parse(result.directory).host if name.nil? || name.empty?
      Decision.new(verified: true, agent: { directory: result.directory, key_id: result.key_id, name: name },
                   tier: blocked ? "blocked" : allowed ? "allowed" : "verified",
                   decision: blocked ? :block : allowed ? :allow : :unknown)
    end

    # A cache of directory key sets: fresh for +ttl+, a failed fetch is remembered for +failure_ttl+, a forced refresh
    # (an unknown key id) is allowed once per +refresh_cooldown+, and a failed refresh keeps serving the last good copy.
    class DirectoryCache
      # @param fetch_json [#call] +(url) -> parsed JSON | nil+
      def initialize(fetch_json:, ttl: 600, failure_ttl: 60, refresh_cooldown: 60, max_entries: 1000, now: nil)
        @fetch_json = fetch_json
        @ttl = ttl
        @failure_ttl = failure_ttl
        @cooldown = refresh_cooldown
        @max = max_entries
        @now = now
        @entries = {}
        @mutex = Mutex.new
      end

      def get_keys(url, refresh: false)
        @mutex.synchronize do
          t = clock
          hit = @entries[url]
          ttl = hit && hit[:keys] ? @ttl : @failure_ttl
          return hit[:keys] if hit && t - hit[:at] < ttl && !(refresh && t - hit[:fetched_at] >= @cooldown)

          keys = begin
            doc = @fetch_json.call(url)
            parsed = doc.nil? ? [] : WebBotAuth.parse_directory(doc)
            parsed.empty? ? nil : parsed
          rescue StandardError
            nil
          end
          kept = keys || (hit && hit[:keys])
          @entries.delete(@entries.keys.first) if @entries.size >= @max && !@entries.key?(url)
          @entries[url] = { keys: kept, at: t, fetched_at: t }
          kept
        end
      end

      def clear = @mutex.synchronize { @entries.clear }

      private

      def clock = (@now ? @now.call : Time.now).to_f
    end

    # Fetch a directory without becoming an SSRF tool: https only, no credentials, port 443, no loopback or private or
    # link-local address (every resolved address is checked and the connection goes to the checked address), no
    # redirects, at most 64 KB, 5 seconds.
    module PinnedFetch
      class Refused < StandardError; end

      SPECIAL = %w[0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24
                   192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 ::/128 ::1/128
                   fc00::/7 fe80::/10 ff00::/8 2001:db8::/32 64:ff9b::/96].map { |c| IPAddr.new(c) }.freeze

      module_function

      def special?(addr)
        ip = addr.is_a?(IPAddr) ? addr : IPAddr.new(addr)
        ip = ip.native if ip.ipv6? && ip.ipv4_mapped?
        SPECIAL.any? { |net| net.family == ip.family && net.include?(ip) }
      rescue IPAddr::Error
        true
      end

      def literal_ip?(host)
        IPAddr.new(host)
        true
      rescue IPAddr::Error
        false
      end

      # @return [Object, nil] the parsed JSON, or nil when the answer was not a 2xx within the size limit.
      def call(url, timeout: 5, max_bytes: DIRECTORY_MAX_BYTES, resolve: nil)
        uri = URI.parse(url)
        raise Refused, "not_https" unless uri.scheme == "https"
        raise Refused, "credentials_in_url" if uri.userinfo
        raise Refused, "disallowed_port" unless uri.port == 443

        host = uri.host.to_s.delete_prefix("[").delete_suffix("]")
        raise Refused, "loopback" if host == "localhost" || host.end_with?(".localhost")

        addresses = literal_ip?(host) ? [host] : (resolve ? resolve.call(host) : Resolv.getaddresses(host))
        raise Refused, "unresolvable" if addresses.empty?
        raise Refused, "private_address" if addresses.any? { |a| special?(a) }

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.ipaddr = addresses.first
        http.open_timeout = timeout
        http.read_timeout = timeout
        body = +""
        status = nil
        http.request_get(uri.request_uri, { "accept" => DIRECTORY_MEDIA_TYPE }) do |res|
          status = res.code.to_i
          res.read_body do |chunk|
            body << chunk
            raise Refused, "too_large" if body.bytesize > max_bytes
          end
        end
        status.between?(200, 299) ? JSON.parse(body) : nil
      end
    end

    # A ready-made verifier: directory cache, SSRF-safe fetch, in-memory replay protection and allow / block lists.
    class Verifier
      # @param allow [Array<Hash>] +{ directory:, name: }+ bots you trust.
      # @param block [Array<Hash>] bots you refuse.
      # @param reject_replays [Boolean] refuse a signature whose +nonce+ was already seen.
      # @param fetch_json [#call, nil] override the directory fetch (tests); default {PinnedFetch}.
      def initialize(allow: [], block: [], ttl: 600, refresh_cooldown: 60, skew_seconds: DEFAULT_SKEW_SECONDS,
                     max_lifetime_seconds: DEFAULT_MAX_LIFETIME_SECONDS, reject_replays: false, fetch_json: nil, now: nil)
        @allow = allow
        @block = block
        @skew = skew_seconds
        @max_lifetime = max_lifetime_seconds
        @reject_replays = reject_replays
        @now = now
        @cache = DirectoryCache.new(fetch_json: fetch_json || ->(url) { PinnedFetch.call(url) }, ttl: ttl,
                                    refresh_cooldown: refresh_cooldown, now: now)
        @seen = {}
        @mutex = Mutex.new
      end

      # @return [Atlas::WebBotAuth::Decision]
      def verify(method:, url:, headers:)
        result = verify_result(method: method, url: url, headers: headers)
        WebBotAuth.decide(result, allow: @allow, block: @block)
      end

      # The raw verification {Result}, before your allow / block lists.
      def verify_result(method:, url:, headers:)
        WebBotAuth.verify_request(method: method, url: url, headers: headers, now: @now&.call, skew_seconds: @skew,
                                  max_lifetime_seconds: @max_lifetime, get_keys: @cache.method(:get_keys),
                                  claim_nonce: @reject_replays ? method(:claim_nonce) : nil)
      end

      def clear_cache = @cache.clear

      private

      def claim_nonce(key, expires_at_ms)
        @mutex.synchronize do
          t = ((@now ? @now.call : Time.now).to_f * 1000)
          @seen.delete_if { |_, exp| exp <= t } if @seen.size > 5000
          return false if @seen.size > 20_000 # fail closed rather than grow without bound
          return false if @seen[key] && @seen[key] > t

          @seen[key] = expires_at_ms
          true
        end
      end
    end
  end
end
