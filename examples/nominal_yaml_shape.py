# Source text for review only. This does not prove runtime module integrity.
from yaml import SafeLoader as RestrictedLoader
from yaml import load as parse

parse(text, Loader=RestrictedLoader)
