<script lang="ts">
  let data: any[] = [];
  async function fetchData() {
    try {
      const response = await fetch('http://example.local/api/users/users-list');
      const jsonData = await response.json();
      data = jsonData.out;
      console.log(data);
    } catch(error) {
      console.error('Errore durante il recupero dei dati:', error);
    }
  }
  fetchData();
</script>

<table class="table table-striped">
  <thead class="thead-dark">
    <tr>
      <th>ID</th>
      <th>Username</th>
    </tr>
  </thead>
  <tbody>
    {#each data as item}
      <tr>
        <td>{item.id}</td>
        <td>{item.username}</td>
      </tr>
    {/each}
  </tbody>
</table>
