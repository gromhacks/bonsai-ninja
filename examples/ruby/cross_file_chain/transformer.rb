require_relative 'executor'

def transform_and_forward(value)
  upper = value.upcase
  execute(upper)
end
