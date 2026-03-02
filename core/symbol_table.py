class Role:
    def __init__(self, name, line):
        self.name = name
        self.permissions = []
        self.parents = []
        self.line = line

    def add_permission(self, permission):
        if permission not in self.permissions:
            self.permissions.append(permission)

    def add_parent(self, parent_role):
        if parent_role not in self.parents:
            self.parents.append(parent_role)

    def __repr__(self):
        return f"Role(name={self.name}, permissions={self.permissions}, inherits={self.parents})"


class User:
    def __init__(self, name, line):
        self.name = name
        self.roles = []
        self.line = line

    def assign_role(self, role_name):
        if role_name not in self.roles:
            self.roles.append(role_name)

    def __repr__(self):
        return f"User(name={self.name}, roles={self.roles})"

class SymbolTable:
    def __init__(self):
        self.roles = {}
        self.users = {}

        self.duplicate_roles = []   
        self.duplicate_users = []
        self.mutex_pairs = set()   

    def add_role(self, role_name, line):
        if role_name in self.roles:
            self.duplicate_roles.append((role_name, line))
            return False






        self.roles[role_name] = Role(role_name, line)
        return True

    def get_role(self, role_name):
        return self.roles.get(role_name)
    
    def add_user(self, user_name, line):
        if user_name in self.users:
            self.duplicate_users.append((user_name, line))
            return False

        self.users[user_name] = User(user_name, line)
        return True

    def get_user(self, user_name):
        return self.users.get(user_name)

    def __repr__(self):
        return (
            f"\nSymbolTable:\n"
            f"Roles: {list(self.roles.keys())}\n"
            f"Users: {list(self.users.keys())}\n"
        )