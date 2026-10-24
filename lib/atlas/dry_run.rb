# frozen_string_literal: true

module Atlas
  # What a write answers with +dry_run: true+ (+?dry_run=true+).
  #
  #   plan = Atlas::DryRunResult.from(atlas.secret_keys.create({ name: "ci" }, dry_run: true))
  #   plan.mode      # => "rollback"
  #   plan.validated # => true
  #
  # +mode+ is +native+ (the endpoint's own dry run, validated in full), +rollback+ (the real
  # write ran in a transaction that was rolled back, every side effect held back, validated
  # in full) or +plan+ (validation could not run to the end: see +validation_skipped+).
  DryRunResult = Struct.new(
    :mode, :validated, :method, :path, :changes, :warnings, :would_return, :would_return_status,
    :suppressed, :validation_skipped, :note, :raw,
    keyword_init: true
  ) do
    # Build one from the parsed answer (string or symbol keys).
    def self.from(answer)
      get = ->(k) { answer.key?(k) ? answer[k] : answer[k.to_sym] }
      new(
        mode: get.call("mode"), validated: get.call("validated") == true, method: get.call("method"),
        path: get.call("path"), changes: Array(get.call("changes")), warnings: Array(get.call("warnings")),
        would_return: get.call("would_return"), would_return_status: get.call("would_return_status"),
        suppressed: Array(get.call("suppressed")), validation_skipped: get.call("validation_skipped"),
        note: get.call("note"), raw: answer
      )
    end

    # True when the check ran to the end (+native+ or +rollback+).
    def validated?
      validated == true
    end
  end
end
