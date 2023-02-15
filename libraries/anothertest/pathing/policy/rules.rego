package libraries.anothertest.pathing.policy

monitor[decision] {
  parameters := {
    "attributes": {}
  }

  data.libraries.systemtypes["entitlements:1.0"].library.policy.abac.v1.resource_has_attributes_glob[message]
    with data.library.parameters as parameters

  decision := {
    "allowed": true,
    "entz": set(),
    "message": message
  }
}

monitor[decision] {
  parameters := {
    "attributes": {}
  }

  data.libraries.systemtypes["entitlements:1.0"].library.policy.abac.v1.resource_has_attributes_glob[message]
    with data.library.parameters as parameters

  decision := {
    "allowed": true,
    "entz": set(),
    "message": message
  }
}

monitor[decision] {
  parameters := {
    "resource_attributes": {},
    "user_attributes": {}
  }

  data.libraries.systemtypes["entitlements:1.0"].library.policy.abac.v1.user_and_resource_has_attributes_glob[message]
    with data.library.parameters as parameters

  decision := {
    "allowed": true,
    "entz": set(),
    "message": message
  }
}




monitor[decision] {
  parameters := {
    "attributes": {}
  }

  data.libraries.systemtypes["entitlements:1.0"].library.policy.abac.v1.resource_has_attributes_glob[message]
    with data.library.parameters as parameters

  decision := {
    "allowed": true,
    "entz": set(),
    "message": message
  }
}

# By default, stacks do no allow or deny a request.
#
# Rules that allow a request should be of the form:
# enforce[decision] {
#     input.subject == "user@acme.org"
#     decision := {
#         "allowed": true,
#         "message": "optional message: why request was allowed",
#         "entz": {"optional set", "contains any type of object"}
#     }
# }
#
# Rules that deny a request should be of the form:
# enforce[decision] {
#     input.context.location == "Mars"
#     decision := {
#         "denied": true,
#         "message": "optional message: why request was denied",
#         "entz": {"optional set"}
#     }
# }
#
# If a request is denied by any rule, then the request is denied. So if a
# stack allows a request, but the system policy denies it, then end result
# is a denied request.
