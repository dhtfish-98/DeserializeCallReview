# Source text for review only. No payload or real deserialization is performed.
import pickle as serialization
from yaml import Loader as GeneralLoader
from yaml import load as parse

serialization.loads(untrusted_bytes)
parse(untrusted_text, Loader=GeneralLoader)
