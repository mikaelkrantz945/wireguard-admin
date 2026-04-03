"""WireGuard peer group management."""

from datetime import datetime

from .. import db


def create_group(name: str, description: str = "", acl_profile_id: int = 0) -> dict:
    existing = db.fetchone("SELECT id FROM wg_groups WHERE name = %s", (name,))
    if existing:
        raise ValueError(f"Group '{name}' already exists")
    now = datetime.utcnow().isoformat()
    row = db.query(
        "INSERT INTO wg_groups (name, description, acl_profile_id, created) VALUES (%s,%s,%s,%s) RETURNING id",
        (name, description, acl_profile_id, now),
        fetchone=True, commit=True,
    )
    return dict(db.fetchone("SELECT * FROM wg_groups WHERE id = %s", (row["id"],)))


def update_group(group_id: int, name: str = None, description: str = None, acl_profile_id: int = None) -> dict:
    updates, params = [], []
    if name is not None:
        updates.append("name = %s")
        params.append(name)
    if description is not None:
        updates.append("description = %s")
        params.append(description)
    if acl_profile_id is not None:
        updates.append("acl_profile_id = %s")
        params.append(acl_profile_id)
    if not updates:
        raise ValueError("No fields to update")
    params.append(group_id)
    db.execute(f"UPDATE wg_groups SET {', '.join(updates)} WHERE id = %s", tuple(params))

    # Update all peers in this group to use the group's ACL profile
    if acl_profile_id is not None:
        db.execute(
            "UPDATE wg_peers SET acl_profile_id = %s WHERE group_id = %s",
            (acl_profile_id, group_id),
        )

    return dict(db.fetchone("SELECT * FROM wg_groups WHERE id = %s", (group_id,)))


def delete_group(group_id: int):
    group = db.fetchone("SELECT * FROM wg_groups WHERE id = %s", (group_id,))
    if not group:
        raise ValueError("Group not found")
    # Unlink peers from this group (don't delete them)
    db.execute("UPDATE wg_peers SET group_id = 0 WHERE group_id = %s", (group_id,))
    db.execute("DELETE FROM wg_groups WHERE id = %s", (group_id,))


def list_groups() -> list[dict]:
    groups = db.fetchall("SELECT * FROM wg_groups ORDER BY name")
    for g in groups:
        count = db.fetchone("SELECT COUNT(*) as cnt FROM wg_peers WHERE group_id = %s", (g["id"],))
        g["peer_count"] = count["cnt"] if count else 0
        # Resolve ACL profile name
        if g["acl_profile_id"]:
            profile = db.fetchone("SELECT name FROM wg_acl_profiles WHERE id = %s", (g["acl_profile_id"],))
            g["acl_profile_name"] = profile["name"] if profile else ""
        else:
            g["acl_profile_name"] = ""
    return groups


def get_group(group_id: int) -> dict | None:
    row = db.fetchone("SELECT * FROM wg_groups WHERE id = %s", (group_id,))
    return dict(row) if row else None
