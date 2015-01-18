Rails.application.routes.draw do
  resources :things
  match ':controller(/:action(/:id))(.:format)', via: [:get, :post]
end
