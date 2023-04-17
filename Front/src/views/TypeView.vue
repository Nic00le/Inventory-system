<template>
    <nav aria-label="breadcrumb">
        <ol class="breadcrumb">
            <li class="breadcrumb-item"><a href="/">Home</a></li>
            <li class="breadcrumb-item active" aria-current="page">{{ type }}</li>
            <button type="button" class="btn btn-primary position-absolute top-20 end-0" @click="add">Add</button>
        </ol>
    </nav>
    <div class="row row-cols-1 row-cols-md-3 g-4">
        <TheCards v-for="r in records" :key="r._id" :id="r._id" :type="type" :src="r.image" :title="r.title"
            :descriptions="r.descriptions" :quantity="r.quantity" :comsumes="r.comsume.length" :borrowerId="r.borrow?.borrowerId"
            :borrowerName="r.borrow?.borrowerName" />
    </div>
    <nav aria-label="Page navigation example">
        <ul class="pagination">
            <li class="page-item">
                <a a v-if="currentPage > 1" class="page-link" @click="currentPage--">
                    <span aria-hidden="true">&laquo;</span>
                </a>
            </li>
            <li class="page-item"><a v-if="currentPage > 2" class="page-link" @click="currentPage = currentPage - 2">{{
                    currentPage - 2
            }}</a></li>
            <li class="page-item"><a v-if="currentPage > 1" class="page-link" @click="currentPage--">{{ currentPage - 1
            }}</a></li>
            <li class="page-item"><a class="page-link active">{{ currentPage }}</a></li>
            <li class="page-item"><a v-if="currentPage < pages.length" class="page-link" @click="currentPage++">{{
                    currentPage + 1
            }}</a></li>
            <li class="page-item"><a v-if="currentPage < pages.length - 1" class="page-link"
                    @click="currentPage = currentPage + 2">{{ currentPage + 2 }}</a></li>
            <li class="page-item">
                <a v-if="currentPage < pages.length" class="page-link" @click="currentPage++">
                    <span aria-hidden="true">&raquo;</span>
                </a>
            </li>
        </ul>
    </nav>
</template>

<script>
import TheCards from '@/components/TheCards.vue'
import { ref, onMounted, computed, watch } from "vue";
import { useRoute } from 'vue-router';

export default {
    name: 'TypeView',
    components: {
        TheCards
    },
    setup() {
        const records = ref([]);
        const lastPage = ref(0);
        const perPage = ref(6);
        const route = useRoute();
        const type = route.params.type;
        const currentPage = ref(1);

        const add = async function () {
            location.assign("/" + route.params.type + "/detail")
        }

        const pages = computed(() => {
            var pages = [];

            for (var i = 1; i <= lastPage.value; i++) {
                pages.push(i)
            }

            return pages;
        })

        const fetchPage = async function (page) {

            var response = await fetch("/api/" + type + "?perPage=" + perPage.value + "&page=" + page);


            if (response.ok) {
                var data = await response.json();
                records.value = data.records;
                lastPage.value = data.pages;
            } else {
                alert(response.statusText);
            }

        };


        onMounted(function () {
            fetchPage(1);
            // alert(props.msg)
        });

        watch(currentPage, () => {
            fetchPage(currentPage.value)
        });

        return {
            records,
            pages,
            fetchPage,
            type,
            currentPage,
            add
        };
    }
}
</script>