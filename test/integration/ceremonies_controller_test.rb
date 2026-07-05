# frozen_string_literal: true

require "test_helper"
require "action_controller"
require "action_controller/test_case"

# A real controller (not the Hash-backed FakeController) so the ceremony concern
# is exercised end to end: through ActionController::Parameters, a genuine
# session, JSON rendering, and the router — the things a plain Hash can't catch.
class PasskeysController < ActionController::Base
  include Passkeyed::Ceremonies

  def registration_options
    render json: passkey_registration_options(User.find(params[:user_id]))
  end

  def register
    passkey_register!(User.find(params[:user_id]), params[:credential], nickname: params[:nickname])
    render json: { status: "ok" }
  rescue Passkeyed::Error => e
    render json: { error: e.message }, status: :unprocessable_entity
  end

  def authentication_options
    render json: passkey_authentication_options
  end

  def authenticate
    user = passkey_authenticate!(params[:credential])
    render json: { user_id: user.id }
  rescue Passkeyed::AuthenticationError
    render json: { error: "Authentication failed" }, status: :unauthorized
  end
end

module Passkeyed
  class CeremoniesControllerTest < ActionController::TestCase
    tests PasskeysController

    setup do
      @user = User.create!(email: "request@example.test")
      @client = WebAuthn::FakeClient.new(TEST_ORIGIN)
      @routes = ActionDispatch::Routing::RouteSet.new
      @routes.draw do
        post "registration_options" => "passkeys#registration_options"
        post "register" => "passkeys#register"
        post "authentication_options" => "passkeys#authentication_options"
        post "authenticate" => "passkeys#authenticate"
      end
    end

    def test_registration_then_authentication_round_trip
      register_via_request(nickname: "Laptop")

      assert_response :success
      credential = @user.passkeyed_credentials.sole

      assert_equal "Laptop", credential.nickname

      post :authentication_options
      options = response.parsed_body
      assertion = @client.get(challenge: options["challenge"], user_verified: true)

      post :authenticate, params: { credential: assertion }, as: :json

      assert_response :success
      assert_equal @user.id, response.parsed_body["user_id"]
    end

    def test_malformed_credential_yields_unprocessable_entity_not_server_error
      post :registration_options, params: { user_id: @user.id }

      post :register, params: { user_id: @user.id, credential: { junk: 1 } }, as: :json

      assert_response :unprocessable_entity
      assert_equal 0, @user.passkeyed_credentials.count
    end

    private

    # Drive a real registration request: fetch options over HTTP, have the fake
    # authenticator sign the JSON-encoded challenge, and POST the credential back
    # as ActionController::Parameters.
    def register_via_request(nickname: nil)
      post :registration_options, params: { user_id: @user.id }
      options = response.parsed_body
      raw = @client.create(challenge: options["challenge"], user_verified: true)

      post :register, params: { user_id: @user.id, credential: raw, nickname: nickname }, as: :json
    end
  end
end
