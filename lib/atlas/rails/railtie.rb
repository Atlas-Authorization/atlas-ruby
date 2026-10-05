# frozen_string_literal: true

# Defined only inside a Rails app. Requiring "atlas/rails" from a plain Ruby
# process (no Rails loaded) leaves this a no-op — the Railtie never comes into
# being, so nothing tries to touch a middleware stack that isn't there.
if defined?(::Rails::Railtie)
  module Atlas
    module Rails
      # Wires the integration into the host Rails app with no manual steps:
      # inserts the auth middleware and mixes the controller helpers into every
      # controller once ActionController loads.
      class Railtie < ::Rails::Railtie
        initializer "atlas.middleware" do |app|
          app.middleware.use Atlas::Rails::Middleware
        end

        initializer "atlas.controller" do
          ActiveSupport.on_load(:action_controller) do
            include Atlas::Rails::Controller
          end
        end
      end
    end
  end
end
