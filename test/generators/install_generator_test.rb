# frozen_string_literal: true

require "test_helper"
require "fileutils"
require "rails/generators"
require "rails/generators/test_case"
require "generators/passkeyed/install/install_generator"

# A namespaced owner model whose real table is "users" (namespaces are
# demodulized for table names). Used to prove the migration targets the real
# table, not "admin/users".
module Admin
  class User < ActiveRecord::Base
    self.table_name = "users"
  end
end

module Passkeyed
  module Generators
    class InstallGeneratorTest < Rails::Generators::TestCase
      tests Passkeyed::Generators::InstallGenerator
      destination File.expand_path("../../tmp/generator", __dir__)
      setup :prepare_destination

      def test_generates_migration_initializer_controller_and_include
        prepare_app
        run_generator

        assert_migration "db/migrate/create_passkeyed_credentials.rb" do |migration|
          assert_match(/add_column :users, :webauthn_id, :string/, migration)
          assert_match(/t\.text :public_key/, migration)
          assert_match(/t\.datetime :last_used_at/, migration)
          assert_match(/t\.boolean :backup_eligible/, migration)
          assert_match(/t\.boolean :backed_up/, migration)
          assert_match(/t\.string :transports/, migration)
          assert_match(/t\.string :aaguid/, migration)
          assert_match(/find_each/, migration) # backfill present
        end
        assert_file "config/initializers/passkeyed.rb"
        assert_file "app/javascript/controllers/passkey_controller.js"
        assert_file "app/models/user.rb", /^\s*include Passkeyed::Model/
      end

      def test_the_stimulus_controller_has_no_javascript_dependency
        prepare_app
        run_generator

        controller = File.read(File.join(destination_root, "app/javascript/controllers/passkey_controller.js"))

        # The controller rides the native PublicKeyCredential JSON methods; the
        # only import allowed is Stimulus itself.
        assert_equal ["@hotwired/stimulus"], controller.scan(/from "([^"]+)"/).flatten.uniq
        assert_match(/parseCreationOptionsFromJSON/, controller)
      end

      def test_is_idempotent_on_a_re_run
        prepare_app
        run_generator
        run_generator # second run must not duplicate the include

        model = File.read(File.join(destination_root, "app/models/user.rb"))

        assert_equal 1, model.scan("include Passkeyed::Model").length
      end

      def test_namespaced_owner_targets_the_real_table
        prepare_app
        write("app/models/admin/user.rb", "module Admin\n  class User < ApplicationRecord\n  end\nend\n")

        run_generator ["--user=Admin::User"]

        assert_migration "db/migrate/create_passkeyed_credentials.rb" do |migration|
          assert_match(/add_column :users, :webauthn_id/, migration)
          refute_match(%r{admin/users}, migration)
        end
        assert_file "app/models/admin/user.rb", /^\s*include Passkeyed::Model/
      end

      private

      def prepare_app
        write("app/models/user.rb", "class User < ApplicationRecord\nend\n")
      end

      def write(path, content)
        full = File.join(destination_root, path)
        FileUtils.mkdir_p(File.dirname(full))
        File.write(full, content)
      end
    end
  end
end
