class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception



  private

    def authenticate_user
      redirect_uri = CGI.escape("http://localhost:3000/auth")
      foursquare_url = "https://foursquare.com/oauth2/authenticate?client_id=SP44HEZDCZIU3UXYDB5X42JWJSU2HC4WEBQGRLAIGUCZX03C&response_type=code&redirect_uri=http://localhost:3000/auth"
      redirect_to foursquare_url unless logged_in?
    end

    def logged_in?
      !!session[:token]
    end
end
