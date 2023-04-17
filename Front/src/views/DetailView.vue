<template>
  <nav aria-label="breadcrumb">
    <ol class="breadcrumb">
      <li class="breadcrumb-item"><a href="/">Home</a></li>
      <li class="breadcrumb-item"><a :href="path">{{ type }}</a></li>
      <li class="breadcrumb-item active" aria-current="page">{{ type }} Detail</li>
    </ol>
  </nav>
  <div v-if="$route.params.type == 'books'">
    <BookForm :newRecord="newRecord" :id="id" />
  </div>
  <div v-if="$route.params.type == 'games'">
    <GameForm :newRecord="newRecord" :id="id" />
  </div>
  <div v-if="$route.params.type == 'gifts'">
    <GiftForm :newRecord="newRecord" :id="id" />
  </div>
  <div v-if="$route.params.type == 'materials'">
    <MaterialForm :newRecord="newRecord" :id="id" />
  </div>
</template>

<script>

import BookForm from "@/components/BookForm.vue";
import GameForm from "@/components/GameForm.vue";
import GiftForm from "@/components/GiftForm.vue";
import MaterialForm from "@/components/MaterialForm.vue";
import { useRoute } from 'vue-router';

export default {
  name: 'DetailView',
  components: {
    BookForm,
    GameForm,
    GiftForm,
    MaterialForm
  }, setup() {
    var newRecord = true;
    const route = useRoute();
    if(route.params.id){
      newRecord = false;
    }
    const id = route.params.id;
    const type = route.params.type;
    const path = "/" + type;

    console.log(newRecord)
    console.log(id)
    console.log(type)
    return {
      id,
      type,
      newRecord,
      path
    }

  }
}
</script>