# frozen_string_literal: true

require "rails/generators"
require "rails/generators/active_record"

module Passkeyed
  module Generators
    # Wires passkeyed into a host Rails app:
    #
    #   bin/rails generate passkeyed:install
    #
    # Adds the credentials table (and a webauthn_id column on the owner),
    # an initializer, the Stimulus controller, and the model concern.
    class InstallGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      class_option :user,
                   type: :string,
                   default: "User",
                   desc: "Name of the model that owns passkeys"

      def create_migration_file
        migration_template(
          "create_passkeyed_credentials.rb.erb",
          "db/migrate/create_passkeyed_credentials.rb"
        )
      end

      def create_initializer
        template "initializer.rb", "config/initializers/passkeyed.rb"
      end

      def copy_stimulus_controller
        copy_file(
          "passkey_controller.js",
          "app/javascript/controllers/passkey_controller.js"
        )
      end

      def inject_model_concern
        model_path = "app/models/#{owner_model.underscore}.rb"
        full_path = File.join(destination_root, model_path)

        unless File.exist?(full_path)
          say_status :skip, "#{model_path} not found; add `include Passkeyed::Model` to your owner model", :yellow
          return
        end

        source = File.read(full_path)
        class_name = owner_model.demodulize

        # Idempotent: re-running the generator must not inject a second include.
        # Anchor on a real include line (not a bare substring, which a comment or
        # the just-injected snippet would satisfy).
        if source.match?(/^\s*include\s+Passkeyed::Model\b/)
          say_status :identical, "Passkeyed::Model already included in #{model_path}", :blue
          return
        end

        # A single-line body (`class User; end`) can't take an injected line
        # safely, so bail to a manual instruction rather than placing the include
        # outside the class.
        if source.match?(/^\s*class\s+#{Regexp.escape(class_name)}\b[^\n]*;\s*end/)
          say_status :skip, "#{model_path} defines #{class_name} on one line; add `include Passkeyed::Model` manually",
                     :yellow
          return
        end

        # inject_into_class places the include after the class declaration with
        # correct indentation, and handles namespaced/indented definitions.
        inject_into_class model_path, class_name, "  include Passkeyed::Model\n"

        # inject_into_class is a silent no-op when the class can't be matched, so
        # confirm the include actually landed rather than reporting false success.
        return if File.read(full_path).match?(/^\s*include\s+Passkeyed::Model\b/)

        say_status :skip, "could not edit #{model_path}; add `include Passkeyed::Model` manually", :yellow
      end

      def print_next_steps
        say "\npasskeyed installed. Next:", :green
        say "  1. bin/rails db:migrate"
        say "  2. add routes + a controller using Passkeyed::Ceremonies (see the README)"
      end

      private

      def owner_model
        options[:user]
      end

      # Used by the migration template. Resolve the real table from the model
      # class so namespaced owners work (Admin::User.table_name => "users");
      # tableize would wrongly produce "admin/users". Fall back to tableize when
      # the class can't be loaded at generate time.
      def owner_table
        owner_model.constantize.table_name
      rescue NameError
        owner_model.tableize
      end
    end
  end
end
