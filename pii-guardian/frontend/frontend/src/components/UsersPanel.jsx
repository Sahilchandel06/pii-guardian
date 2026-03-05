import { apiRequest } from "../lib/api";

export default function UsersPanel({ token, users, reloadUsers, setNotice, setError }) {
  const updateRole = async (id, role) => {
    setNotice("");
    setError("");
    try {
      await apiRequest(`/auth/users/${id}/role`, {
        token,
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ role }),
      });
      setNotice(`Updated user ${id} to ${role}`);
      reloadUsers();
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <section className="panel">
      <h3>User Management</h3>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Username</th>
              <th>Email</th>
              <th>Role</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id}>
                <td>{user.id}</td>
                <td>{user.username}</td>
                <td>{user.email}</td>
                <td>{user.role}</td>
                <td className="action-cell">
                  <button onClick={() => updateRole(user.id, "user")}>Set User</button>
                  <button onClick={() => updateRole(user.id, "admin")}>Set Admin</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
