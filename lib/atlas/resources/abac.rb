# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class Abac < Base
      # List the ABAC policies (current version of each).
      # Scope: abac:read. query: limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/abac_policies", query: query)
      end

      # Create an ABAC policy from +source+ written in the Cedar-subset policy language
      # (permit/forbid with when/unless over principal, action, resource and context attributes;
      # +fga.check(...)+ consults the policy’s FGA store). Source that does not parse is refused
      # with the character position; with an entity schema set it is also type-checked and every
      # problem is reported. Optional +tests+ are saved with version 1.
      # Scope: abac:write. query: dry_run.
      def create(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/abac_policies",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Read one ABAC policy with its current source and tests.
      # Scope: abac:read.
      def get(id)
        request(method: :get, path: "/v1/abac_policies/#{enc(id)}")
      end

      # Update an ABAC policy. Sending +source+ appends a new version and makes it current;
      # +current_version+ (without +source+) rolls back to an earlier version; name, description,
      # enabled and fga_store_id change in place.
      # Scope: abac:write. query: dry_run.
      def update(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/abac_policies/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Delete an ABAC policy and all its versions.
      # Scope: abac:write. query: dry_run.
      def delete(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/abac_policies/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # List every saved version of an ABAC policy, newest first.
      # Scope: abac:read. query: limit, starting_after.
      def versions(id, query = nil)
        request(method: :get, path: "/v1/abac_policies/#{enc(id)}/versions", query: query)
      end

      # Run test cases against a policy version (default: the current one), or against a draft
      # +source+ and +tests+ sent in the body, without saving anything. Each test is a request plus
      # the expected decision; the policy is evaluated on its own, not with the rest of the set. The
      # response also carries +coverage+: which rules and +when+/+unless+ clauses the tests
      # exercised (a clause no test saw both true and false is listed as a gap), with line numbers.
      # Scope: abac:read. query: dry_run.
      def test(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/abac_policies/#{enc(id)}/test",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Policy decision point: ask whether +principal+ may perform +action+ on +resource+ given
      # +context+ (and optional extra +entities+ for hierarchy). All enabled policies are evaluated
      # together with Cedar semantics: a matching forbid wins, otherwise a matching permit allows,
      # otherwise deny. Each decision is written to the event feed (type authz.decision), so log
      # streams carry it.
      # Scope: abac:evaluate. query: dry_run.
      def evaluate(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/abac/evaluate",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Partial evaluation (data filtering): ask what is left of the decision when an entity is
      # unknown. With a known principal, an action and a resource TYPE, the response is a residual
      # +filter+ over the resource attributes (or constant +true+/+false+) that is equivalent to
      # evaluating the policies on each resource. +unknowns: ["principal"]+ answers "who may do this
      # on that resource". Relationship conditions (+fga.check+) are resolved to id lists from the
      # policy’s FGA store unless +resolve_relations+ is false. +output+ asks for a ready-made
      # parameterised SQL WHERE (+sql+: dialect and a field-to-column map) and/or a Prisma where
      # object (+prisma+: a field map). Policies that build sets from unknown attributes cannot be
      # expressed as a filter and are refused with a message naming the policy.
      # Scope: abac:evaluate. query: dry_run. body requires: principal, action, resource.
      def partial_evaluate(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/abac/partial_evaluate",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # List the resources of a type a principal may perform an action on, paged (+limit+,
      # +starting_after+; the response carries +has_more+ and +next_cursor+). Candidates are the
      # Atlas resources of that type (their metadata are the attributes) or the +candidates+ you
      # send. The policies are reduced to one filter and applied to every candidate; +method+ says
      # whether that worked or each candidate was evaluated in full.
      # Scope: abac:evaluate. query: dry_run. body requires: principal, action, resource_type.
      def accessible_resources(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/abac/accessible_resources",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Compare two versions of a policy: a line diff of the source and, unless +semantic=false+,
      # the requests whose decision changes. The semantic part enumerates a bounded set of requests
      # built from the attributes, groups and actions the policies test (from the entity schema when
      # one is set), and lists those that come out differently, with newly-allowed and newly-denied
      # counts per action. +exhaustive+ says whether every request in the space was compared or the
      # space was sampled.
      # Scope: abac:read. query: from, to, semantic, max_requests, max_changes.
      def diff(id, query = nil)
        request(method: :get, path: "/v1/abac_policies/#{enc(id)}/diff", query: query)
      end

      # The same comparison for two policy sources you send (a draft against the saved version, or
      # two templates), without saving anything.
      # Scope: abac:read. query: dry_run. body requires: before, after.
      def diff_sources(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/abac/diff",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # AuthZEN Access Evaluation: +{subject, resource, action, context}+ → +{decision: boolean}+.
      # Entity types map to PascalCase policy types.
      # Scope: abac:evaluate. query: dry_run.
      def authzen_evaluation(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/authzen/access/v1/evaluation",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # AuthZEN Access Evaluations (batch, up to 100): shared defaults plus an +evaluations+ array,
      # with +options.evaluations_semantic+ of execute_all (default), deny_on_first_deny or
      # permit_on_first_permit.
      # Scope: abac:evaluate. query: dry_run.
      def authzen_evaluations(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/authzen/access/v1/evaluations",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # AuthZEN Subject Search: which subjects of +subject.type+ may perform +action+ on +resource+
      # (give the resource a +type+ and +id+). Answers from the same ABAC policies as an evaluation,
      # reduced once by partial evaluation and applied to the candidates Atlas knows: your users
      # (type +user+, their public metadata as attributes) and the users in the FGA stores the
      # policies consult. +page.limit+ and +page.token+ page the result; the response carries
      # +page.next_token+ (empty on the last page), +count+ and +total+.
      # Scope: abac:evaluate. query: dry_run. body requires: subject, action, resource.
      def authzen_search_subject(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/authzen/access/v1/search/subject",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # AuthZEN Resource Search: which resources of +resource.type+ the +subject+ may perform
      # +action+ on. Candidates are your synced Atlas resources of that type (their metadata are the
      # attributes) and the objects of that type in the FGA stores the policies consult. Paged with
      # +page.limit+ and +page.token+.
      # Scope: abac:evaluate. query: dry_run. body requires: subject, action, resource.
      def authzen_search_resource(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/authzen/access/v1/search/resource",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # AuthZEN Action Search: which actions the +subject+ may perform on the +resource+. The
      # actions considered are the ones the policies name (and the entity schema declares), each
      # evaluated in full; the result lists the permitted action names.
      # Scope: abac:evaluate. query: dry_run. body requires: subject, resource.
      def authzen_search_action(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/authzen/access/v1/search/action",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      def templates
        @templates ||= Templates.new(@transport)
      end

      def links
        @links ||= Links.new(@transport)
      end

      def schema
        @schema ||= Schema.new(@transport)
      end

      class Templates < Base
        # List the ABAC policy templates, with their slots and how many links each has.
        # Scope: abac:read. query: limit, starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/abac_templates", query: query)
        end

        # Create a policy template: policy source whose scope uses the slots +?principal+ and/or
        # +?resource+ (+principal == ?principal+, +resource in ?resource+, +resource is Doc in
        # ?resource+). Slots are filled by a link. With an entity schema set, the template is
        # type-checked on save (a slot stands for any entity type).
        # Scope: abac:write. query: dry_run. body requires: name, source.
        def create(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/abac_templates",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Read one policy template.
        # Scope: abac:read.
        def get(id)
          request(method: :get, path: "/v1/abac_templates/#{enc(id)}")
        end

        # Change a template. A new +source+ bumps +version+ and takes effect on every link at once
        # (+links_updated+ counts them). It is refused, with one error per problem and the link
        # named, if any link could no longer be filled in or would fail the entity schema.
        # Scope: abac:write. query: dry_run.
        def update(id, body, query = nil, idempotency_key: nil)
          request(
            method: :patch,
            path: "/v1/abac_templates/#{enc(id)}",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Delete a template. A template with links is refused with 409 unless +force=true+, which
        # deletes the links too.
        # Scope: abac:write. query: dry_run, force.
        def delete(id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/abac_templates/#{enc(id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end

      class Links < Base
        # List template links: a template with its slots filled by entities. Each link’s +source+ is
        # what the policy engine evaluates.
        # Scope: abac:read. query: template_id, limit, starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/abac_policy_links", query: query)
        end

        # Link a template to entities. Every slot the template uses needs its entity (+principal+
        # for +?principal+, +resource+ for +?resource+); one it does not use is refused. The link is
        # evaluated together with the other enabled policies, always from the template’s current
        # source, and is type-checked against the entity schema when one is set.
        # Scope: abac:write. query: dry_run. body requires: template_id, name.
        def create(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/abac_policy_links",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Read one template link.
        # Scope: abac:read.
        def get(id)
          request(method: :get, path: "/v1/abac_policy_links/#{enc(id)}")
        end

        # Rename, enable or disable a link, or point its slots at other entities.
        # Scope: abac:write. query: dry_run.
        def update(id, body, query = nil, idempotency_key: nil)
          request(
            method: :patch,
            path: "/v1/abac_policy_links/#{enc(id)}",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Delete a link; the template stays.
        # Scope: abac:write. query: dry_run.
        def delete(id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/abac_policy_links/#{enc(id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end

      class Schema < Base
        # The instance’s ABAC entity schema (+schema+ is null and +version+ 0 when none is set).
        # Scope: abac:read.
        def get
          request(method: :get, path: "/v1/abac_schema")
        end

        # Set the ABAC entity schema: +entity_types+ (attributes with +boolean+, +long+, +string+,
        # +set+, +entity+ and +record+ types, +required: false+ for optional ones, and +member_of+)
        # and +actions+ (+applies_to+ principal and resource types and a +context+). Every problem
        # is reported with its path. Once set, policies and templates are type-checked when saved:
        # unknown attributes, optional attributes read without a +has+ guard, wrong operand types,
        # unknown entity types and actions, and actions that do not apply to the policy’s principal
        # and resource types. The response lists the errors the schema would give the policies and
        # links already stored.
        # Scope: abac:write. query: dry_run. body requires: schema.
        def set(body, query = nil, idempotency_key: nil)
          request(
            method: :put,
            path: "/v1/abac_schema",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Remove the entity schema; policies are no longer type-checked.
        # Scope: abac:write. query: dry_run.
        def delete(query = nil, idempotency_key: nil)
          request(method: :delete, path: "/v1/abac_schema", query: query, idempotency_key: idempotency_key)
        end

        # Type-check policy (or, with +template: true+, template) source against the saved schema,
        # or one sent as +schema+, without saving anything. Returns every issue with its policy
        # number, clause, character offset, line and column. A syntax error is reported as an issue
        # too.
        # Scope: abac:read. query: dry_run. body requires: source.
        def validate(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/abac_schema/validate",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end
      end
    end
  end
end
