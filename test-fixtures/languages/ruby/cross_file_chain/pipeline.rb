require_relative 'transformer'

def run_pipeline(payload)
  wrapped = "[#{payload}]"
  transform_and_forward(wrapped)
end
