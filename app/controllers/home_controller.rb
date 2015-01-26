class HomeController < ApplicationController
  def index
    render inline: ENV['API_AUTH_NAME']
  end
end
