class User < ActiveRecord::Base
  rolify
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
  validates :username, presence: true, uniqueness: true #, format: { with: /[a-zA-Z0-9]{4,20}/ }
  # attr_accessible :email, :password, :password_confirmation, :remember_me, :username
end
