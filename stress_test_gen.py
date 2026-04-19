import os

def generate_mega_policy(num_roles=100):
    # Ensure the folder exists so we don't get a FileNotFoundError
    if not os.path.exists("dsl"):
        os.makedirs("dsl")
        
    policy = []
    
    # 1. Generate Roles with a structured tree inheritance
    for i in range(num_roles):
        parent_id = i // 5  # Every 5 roles share a parent
        if i == 0:
            policy.append(f"role Role_{i} {{ permissions: [perm_{i}] }}")
        else:
            policy.append(f"role Role_{i} extends Role_{parent_id} {{ permissions: [perm_{i}] }}")
    
    # 2. Add some Conflict Rules (Mutex)
    policy.append("\n# Separation of Duty Rules")
    policy.append("mutex Role_10 Role_20")
    
    # 3. Add Users
    policy.append("\n# Test Users")
    policy.append("user Auditor { roles: [Role_10, Role_20] }")

    # FIX: Ensure this is a STRING in quotes
    file_path = "dsl/large_scale_test.rbac"
    
    with open(file_path, "w") as f:
        f.write("\n".join(policy))
    
    print(f"✅ Success! Generated {num_roles} roles in {file_path}")

if __name__ == "__main__":
    generate_mega_policy(100)