# Role-Based Access Control (RBAC)

This document provides an overview of the Role-Based Access Control (RBAC) system implemented in Scrambled Eggs.

## Overview

The RBAC system allows you to control access to different parts of the application by assigning permissions to roles, and then assigning those roles to users. This provides a flexible and maintainable way to manage user permissions.

## Core Concepts

### Permissions

Permissions define what actions can be performed on resources. Each permission has:
- A unique name (e.g., `user:read`)
- A resource (e.g., `user`)
- An action (e.g., `read`)
- An optional description

### Roles

Roles are collections of permissions. Users are assigned roles, which determine what they can do in the system. Some default roles are provided:
- `superadmin`: Full access to everything
- `admin`: Administrative access
- `moderator`: Limited administrative access
- `user`: Regular user (default for new users)
- `guest`: Limited access

### Users

Users can be assigned one role, which determines their permissions in the system.

## API Endpoints

### Roles

- `GET /api/v1/rbac/roles/` - List all roles
- `POST /api/v1/rbac/roles/` - Create a new role
- `GET /api/v1/rbac/roles/{role_id}` - Get role details
- `PUT /api/v1/rbac/roles/{role_id}` - Update a role
- `DELETE /api/v1/rbac/roles/{role_id}` - Delete a role

### Permissions

- `GET /api/v1/rbac/permissions/` - List all permissions
- `POST /api/v1/rbac/permissions/` - Create a new permission

### User Roles

- `POST /api/v1/rbac/users/{user_id}/roles/{role_name}` - Assign a role to a user
- `GET /api/v1/rbac/me/permissions` - Get current user's permissions

## Usage Examples

### Creating a New Role

```http
POST /api/v1/rbac/roles/
Authorization: Bearer your_token
Content-Type: application/json

{
  "name": "content_moderator",
  "description": "Can moderate user content",
  "permissions": [
    "content:read",
    "content:update",
    "content:delete"
  ]
}
```

### Assigning a Role to a User

```http
POST /api/v1/rbac/users/123/roles/content_moderator
Authorization: Bearer your_token
```

### Checking Permissions in Code

```python
from fastapi import Depends, HTTPException
from app.api.deps.rbac import Permissions

# Protect a route with a permission check
@router.get("/protected-route")
async def protected_route(
    current_user: User = Depends(Permissions.USER_READ)
):
    # This code will only run if the user has the user:read permission
    return {"message": "You have access!"}

# Or check permissions manually
rbac_service = RBACService(db)
if not rbac_service.has_permission(user, "resource:action"):
    raise HTTPException(status_code=403, detail="Permission denied")
```

## Default Permissions

The system comes with several default permissions:

### User Management
- `user:create` - Create new users
- `user:read` - View user information
- `user:update` - Update user information
- `user:delete` - Delete users

### Role Management
- `role:create` - Create roles
- `role:read` - View roles
- `role:update` - Update roles
- `role:delete` - Delete roles

### Admin
- `admin:access` - Access admin dashboard
- `admin:settings` - Modify system settings

### Messages
- `message:send` - Send messages
- `message:delete` - Delete messages
- `message:edit` - Edit messages

### Channels
- `channel:create` - Create channels
- `channel:read` - View channels
- `channel:update` - Update channels
- `channel:delete` - Delete channels

## Best Practices

1. **Principle of Least Privilege**: Only grant the minimum permissions necessary for a role to function.
2. **Role Naming**: Use clear, descriptive names for roles (e.g., `content_moderator` instead of `mod1`).
3. **Audit Logging**: Log all permission changes for security auditing.
4. **Regular Reviews**: Periodically review roles and permissions to ensure they're still appropriate.
5. **Testing**: Always test permission changes in a development environment first.

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Verify the user's role has the required permission
   - Check for typos in permission names
   - Ensure the user's session is still valid

2. **Role Not Found**
   - Check if the role exists
   - Verify the role name is spelled correctly
   - Ensure the role hasn't been deleted

3. **Cannot Delete Role**
   - Make sure no users are assigned to the role
   - Check for any dependencies on the role

For additional help, contact your system administrator.
