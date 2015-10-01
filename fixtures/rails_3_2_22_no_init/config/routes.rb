Rails3212::Application.routes.draw do
  resources :things
  match ':controller(/:action(/:id))(.:format)'
end
