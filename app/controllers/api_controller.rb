class ApiController < ApplicationController  
  http_basic_authenticate_with name:ENV["API_AUTH_NAME"], password:ENV["API_AUTH_PASSWORD"], :only => [:signup, :signin, :get_token]  
  before_filter :check_for_valid_authtoken, :except => [:signup, :signin, :get_token]
  IMAGE_FOLD = 'public/imgs'

  def signup
    if request.post?
      if params && params[:full_name] && params[:email] && params[:password]
        
        params[:user] = Hash.new    
        params[:user][:first_name] = params[:full_name].split(" ").first
        params[:user][:last_name] = params[:full_name].split(" ").last
        params[:user][:email] = params[:email]
        
        begin 
          decrypted_pass = AESCrypt.decrypt(params[:password], ENV["API_AUTH_PASSWORD"])
        rescue Exception => e
          decrypted_pass = nil          
        end
                
        params[:user][:password] = decrypted_pass  
        params[:user][:verification_code] = rand_string(20)
        
        user = User.new(user_params)

        if user.save
          render :json => user.to_json, :status => 200
        else
          error_str = ""

          user.errors.each{|attr, msg|           
            error_str += "#{attr} - #{msg},"
          }
                    
          e = Error.new(:status => 400, :message => error_str)
          logger.info e.to_json 
          render :json => e.to_json, :status => 400
        end
      else
        e = Error.new(:status => 400, :message => "required parameters are missing")
        render :json => e.to_json, :status => 400
      end
    end
  end

  def signin
    if request.post?
      if params && params[:email] && params[:password]        
        user = User.where(:email => params[:email]).first
                      
        if user 
          if User.authenticate(params[:email], params[:password]) 
                    
            if !user.api_authtoken || (user.api_authtoken && user.authtoken_expiry < Time.now)
              auth_token = rand_string(20)
              auth_expiry = Time.now + (24*60*60)
          
              user.update_attributes(:api_authtoken => auth_token, :authtoken_expiry => auth_expiry)    
            end 
                                   
            render :json => user.to_json, :status => 200
          else
            e = Error.new(:status => 401, :message => "Wrong Password")
            render :json => e.to_json, :status => 401
          end      
        else
          e = Error.new(:status => 400, :message => "No USER found by this email ID")
          render :json => e.to_json, :status => 400
        end
      else
        e = Error.new(:status => 400, :message => "required parameters are missing")
        render :json => e.to_json, :status => 400
      end
    end
  end
  
  def reset_password
    if request.post?
      if params && params[:old_password] && params[:new_password]         
        if @user         
          if @user.authtoken_expiry > Time.now
            authenticate_user = User.authenticate(@user.email, params[:old_password])
                        
            if authenticate_user && !authenticate_user.nil?             
              auth_token = rand_string(20)
              auth_expiry = Time.now + (24*60*60)
            
              begin
                new_password = AESCrypt.decrypt(params[:new_password], ENV["API_AUTH_PASSWORD"])  
              rescue Exception => e
                new_password = nil
                puts "error - #{e.message}"
              end
              
              new_password_salt = BCrypt::Engine.generate_salt
              new_password_digest = BCrypt::Engine.hash_secret(new_password, new_password_salt)
                              
              @user.update_attributes(:password => new_password, :api_authtoken => auth_token, :authtoken_expiry => auth_expiry, :password_salt => new_password_salt, :password_hash => new_password_digest)
              render :json => @user.to_json, :status => 200           
            else
              e = Error.new(:status => 401, :message => "Wrong Password")
              render :json => e.to_json, :status => 401
            end
          else
            e = Error.new(:status => 401, :message => "Authtoken is invalid or has expired. Kindly refresh the token and try again!")
            render :json => e.to_json, :status => 401
          end
        else
          e = Error.new(:status => 400, :message => "No user record found for this email ID")
          render :json => e.to_json, :status => 400
        end
      else
        e = Error.new(:status => 400, :message => "required parameters are missing")
        render :json => e.to_json, :status => 400
      end
    end
  end
  
  def get_token
    if params && params[:email]    
      user = User.where(:email => params[:email]).first
    
      if user 
        if !user.api_authtoken || (user.api_authtoken && user.authtoken_expiry < Time.now)          
          auth_token = rand_string(20)
          auth_expiry = Time.now + (24*60*60)
          
          user.update_attributes(:api_authtoken => auth_token, :authtoken_expiry => auth_expiry)                              
        end        
        
        render :json => user.to_json(:only => [:api_authtoken, :authtoken_expiry])                
      else
        e = Error.new(:status => 400, :message => "No user record found for this email ID")
        render :json => e.to_json, :status => 400
      end
      
    else
      e = Error.new(:status => 400, :message => "required parameters are missing")
      render :json => e.to_json, :status => 400
    end
  end

  def clear_token
    if @user.api_authtoken && @user.authtoken_expiry > Time.now
      @user.update_attributes(:api_authtoken => nil, :authtoken_expiry => nil)
          
      m = Message.new(:status => 200, :message => "Token cleared")          
      render :json => m.to_json, :status => 200  
    else
      e = Error.new(:status => 401, :message => "You don't have permission to do this task")
      render :json => e.to_json, :status => 401
    end 
  end
  
  def upload_photo
    if request.post?
      if params[:title] && params[:image]          
        if @user && @user.authtoken_expiry > Time.now
          rand_id = rand_string(40)
          image_name = params[:image].original_filename
          image = params[:image].read     

          File.open(File.join(IMAGE_FOLD, rand_id), 'wb') do |f|
            f.write(image)
          end
                    
          image_url = "#{request.protocol + request.host_with_port}/imgs/#{rand_id}"
                                                  
          photo = Photo.new(:name => image_name, :user_id => @user.id, :title => params[:title], :image_url => image_url, :random_id => rand_id)
        
          if photo.save
            render :json => photo.to_json
          else
            error_str = ""

            photo.errors.each{|attr, msg|           
              error_str += "#{attr} - #{msg},"
            }
                  
            e = Error.new(:status => 400, :message => error_str)
            render :json => e.to_json, :status => 400
          end
        else
          e = Error.new(:status => 401, :message => "Authtoken has expired")
          render :json => e.to_json, :status => 401
        end
      else
        e = Error.new(:status => 400, :message => "required parameters are missing")
        render :json => e.to_json, :status => 400
      end
    end
  end

  def delete_photo
    if request.delete?
      if params[:photo_id]          
        if @user && @user.authtoken_expiry > Time.now
          photo = Photo.where(:random_id => params[:photo_id]).first
          
          if photo && photo.user_id == @user.id            
            File.delete(File.join(IMAGE_FOLD, photo.rand_id)) rescue nil                            
            if photo.destroy
              m = Message.new(:status => 200, :message => "Image deleted")          
              render :json => m.to_json, :status => 200  
            else
              e = Error.new(:status => 401, :message => "Can not delete picture")
              render :json => e.to_json, :status => 401        
            end                        
          else
            e = Error.new(:status => 401, :message => "Invalid Photo ID or You don't have permission to delete this photo!")
            render :json => e.to_json, :status => 401
          end
        else
          e = Error.new(:status => 401, :message => "Authtoken has expired. Please get a new token and try again!")
          render :json => e.to_json, :status => 401
        end
      else
        e = Error.new(:status => 400, :message => "required parameters are missing")
        render :json => e.to_json, :status => 400
      end
    end
  end

  def get_photos    
    if @user && @user.authtoken_expiry > Time.now
      photos = @user.photos
      render :json => photos.to_json, :status => 200
    else
      e = Error.new(:status => 401, :message => "Authtoken has expired. Please get a new token and try again!")
      render :json => e.to_json, :status => 401
    end
  end

  private 
  
  def check_for_valid_authtoken
    authenticate_or_request_with_http_token do |token, options|     
      @user = User.where(:api_authtoken => token).first      
    end
  end
  
  def rand_string(len)
    o =  [('a'..'z'),('A'..'Z')].map{|i| i.to_a}.flatten
    string  =  (0..len).map{ o[rand(o.length)]  }.join

    return string
  end
  
  def user_params
    params.require(:user).permit(:first_name, :last_name, :email, :password, :password_hash, :password_salt, :verification_code, 
    :email_verification, :api_authtoken, :authtoken_expiry)
  end
  
  def photo_params
    params.require(:photo).permit(:name, :title, :user_id, :random_id, :image_url)
  end
    
end
