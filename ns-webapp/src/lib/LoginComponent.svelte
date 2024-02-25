<script>
  import sessionStore from './session_store';
  let username = '';
  let password = '';
  async function handleSubmit() {
    try {
      const formData = new URLSearchParams();
      formData.append('username', username);
      formData.append('password', password);
      const response = await fetch('/api/users/sign-in', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: formData
      });
      if (response.ok) {
        const data = await response.json();
        sessionStore.set(data.out);
        console.log($sessionStore);
      } else {
        alert('Signin error');
      }
    } catch (error) {
      console.error('Error:', error);
      alert('An error occurred');
    }
  }
</script>

<div class="container mt-5">
  <div class="row justify-content-center">
    <div class="col-md-6">
      <div class="card">
        <div class="card-body">
          <h5 class="card-title">Login</h5>
          <form on:submit|preventDefault={handleSubmit}>
            <div class="mb-3">
              <label for="username" class="form-label">Username</label>
              <input type="text" class="form-control" id="username" bind:value={username} required>
            </div>
            <div class="mb-3">
              <label for="password" class="form-label">Password</label>
              <input type="password" class="form-control" id="password" bind:value={password} required>
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
          </form>
        </div>
      </div>
    </div>
  </div>
</div>
