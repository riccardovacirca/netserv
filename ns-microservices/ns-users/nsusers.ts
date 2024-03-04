export const UserEntity = (id:number) => ({
  id, components:[] as Object[]
});

export const UserDataComponent = (
  id:number, username:string, created_at:string, updated_at:string, deleted_at:string) => ({
  id, username, created_at, updated_at, deleted_at
});

export const UsersListComponent = (entries:any[]) => ({entries});

export const fetchUsersListSystem = async () => {
  try {
    const resp = await fetch(`/api/users`);
    if (!resp.ok) {throw new Error();}
    const data = await resp.json();
    return data; //UsersListComponent(data.entries);
  } catch (error) {
    return null;
  }
};

export const createUserDataSystem = async (uData:any) => {
  try {
    const resp = await fetch('/api/user', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(uData)
    });
    if (!resp.ok) {throw new Error();}
    return await resp.json();
  } catch (error) {
    return null;
  }
};

export const readUserDataSystem = async (uid:number) => {
  try {
    const resp = await fetch(`/api/users/${uid}`);
    if (!resp.ok) {throw new Error();}
    const data = await resp.json();
    const { id, username, created_at, updated_at, deleted_at } = data;
    return UserDataComponent(id, username, created_at, updated_at, deleted_at);
  } catch (error) {
    return null;
  }
};

export const updateUserDataSystem = async (uData:any) => {
  try {
    const resp = await fetch(`/api/user/${uData.id}`, {
      method: 'PUT', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(uData)
    });
    if (!resp.ok) {throw new Error();}
    return JSON.parse(await resp.json());
  } catch (error) {
    return null;
  }
};

export const deleteUserDataSystem = async (user:any) => {
  try {
    const resp = await fetch(`/api/users/${user.id}`, {method: 'DELETE'});
    if (!resp.ok) {throw new Error();}
    return await resp.json();
  } catch (error) {
    return null;
  }
};

if (require.main === module) {
  fetchUsersListSystem()
    .then(data => {
      console.log(data);
    })
    .catch(error => {
      console.error('Error:', error);
    });
}
