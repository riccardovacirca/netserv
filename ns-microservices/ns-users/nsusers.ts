
import * as fs from 'fs';

export const UserEntity = (id:number) => ({
  id, components:[] as any[]
});

export const UserDataComponent = (
  id:number, username:string, createdAt:string, updatedAt:string,
  deletedAt:string) => ({
  id, username, createdAt, updatedAt, deletedAt
});

export const UsersListComponent = (entries:any[]) => ({entries});

export const nsReadConfig = (path) => {
  const conf = fs.readFileSync(path, 'utf-8');
  return JSON.parse(conf);
};

export const nsFetchUsersList = async () => {
  try {
    const resp = await fetch(`http://192.168.1.5:2310/api/users-list`);
    if (!resp.ok) {throw new Error();}
    const data = await resp.json();
    return data; //UsersListComponent(data.entries);
  } catch (error) {
    console.log(error);
    return null;
  }
};

export const nsCreateUserData = async (uData:any) => {
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

export const nsReadUserData = async (uid:number) => {
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

export const nsUpdateUserData = async (uData:any) => {
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

export const nsDeleteUserData = async (user:any) => {
  try {
    const resp = await fetch(`/api/users/${user.id}`, {method: 'DELETE'});
    if (!resp.ok) {throw new Error();}
    return await resp.json();
  } catch (error) {
    return null;
  }
};
