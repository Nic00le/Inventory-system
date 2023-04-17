<template>

  <div class="container-fluid">
    <div class="row">
      <div class="col-sm-6">
        <div class="center">
          <p>



          </p>
          <h1>Inventroy System</h1>
          <p>
            This is a modified jumbrotom that occupies the entire horizontal space of its parent.
          </p>
        </div>
      </div>
      <div class="col-sm-6">
        <apexchart width="380" type="pie" :options="options" :series="series"></apexchart>
      </div>
    </div>
  </div>

  <div v-if="token" class="row">
    <div class="col">
      <RouterLink to="/books">
        <div class="card">
          <img
            src="https://static.vecteezy.com/system/resources/previews/002/896/415/original/books-illustration-cartoon-books-books-vector.jpg"
            class="card-img-top" alt="Books">
          <div class="card-body">
            <h5 class="card-title">Books</h5>
          </div>
        </div>
      </RouterLink>
    </div>
    <div class="col">
      <RouterLink to="/games">
        <div class="card">
          <img src="https://pioneerpages.net/wp-content/uploads/2022/03/istockphoto-1208386205-170667a.jpg"
            class="card-img-top" alt="Games">
          <div class="card-body">
            <h5 class="card-title">Games</h5>
          </div>
        </div>
      </RouterLink>
    </div>
    <div class="col">
      <RouterLink to="/gifts">
        <div class="card">
          <img
            src="https://static.vecteezy.com/system/resources/previews/002/036/695/original/gift-box-cartoon-doodle-hand-drawn-concept-kawaii-illustration-vector.jpg"
            class="card-img-top" alt="Gifts">
          <div class="card-body">
            <h5 class="card-title">Gifts</h5>
          </div>
        </div>
      </RouterLink>
    </div>
    <div class="col">
      <RouterLink to="/materials">
        <div class="card">
          <img
            src="https://img.freepik.com/premium-vector/cartoon-man-with-pencil-ruler-doodle-cute-icon-mathematics-hand-drawn-cartoon-illustration_156892-477.jpg"
            class="card-img-top" alt="Materials">
          <div class="card-body">
            <h5 class="card-title">Materials</h5>
          </div>
        </div>
      </RouterLink>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from "vue";

export default {
  name: 'HomeView',
  setup() {
    let token = localStorage.getItem('token');

    const options = ref({});
    const series = ref([44, 55, 41, 17, 15]);

    onMounted(async () => {
      let token = localStorage.getItem("token");
      console.log(token);

      var response = await fetch("/api/records/aggregate/groupby", {
        headers: {
          "x-access-token": token
        }
      });

      if (response.ok) {
        var records = await response.json();

        series.value = records.map(a => a.count);
        options.value = { labels: records.map(a => a._id) };
      }
    });

    return {
      options, 
      series,
      token
    }
  }
}

</script>