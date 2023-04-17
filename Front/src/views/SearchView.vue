<template>
    <nav aria-label="breadcrumb">
        <ol class="breadcrumb">
            <li class="breadcrumb-item"><a href="/">Home</a></li>
            <li class="breadcrumb-item active" aria-current="page">Search Results</li>
        </ol>
    </nav>
    <div class="row row-cols-1 row-cols-md-3 g-4">
        <TheCards v-for="r in records" :key="r._id" :id="r._id" :type="r.type" :src="r.image" :title="r.title"
            :descriptions="r.descriptions" />
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
import { useRoute } from 'vue-router';
import { ref, watch, onMounted, computed } from 'vue';
import TheCards from '@/components/TheCards.vue';

export default {
    name: 'SearchView',
    components: {
        TheCards
    },
    setup() {
        const records = ref([]);
        const route = useRoute();
        const lastPage = ref(0);
        const currentPage = ref(1);
        const input = route.params.input;
        const perPage = ref(6);

        const pages = computed(() => {
            var pages = [];

            for (var i = 1; i <= lastPage.value; i++) {
                pages.push(i)
            }

            return pages;
        })

        const fetchPage = async function (page) {

            var response = await fetch("/api/search/" + input + "?perPage=" + perPage.value + "&page=" + page);

            if (response.ok) {
                var data = await response.json();
                records.value = data.records;
                lastPage.value = data.pages;
            } else {
                alert(response.statusText);
            }
        };

        watch(currentPage, () => {
            fetchPage(currentPage.value)
        });

        onMounted(function () {
            fetchPage(1)
        })

        return {
            records,
            fetchPage,
            currentPage,
            pages
        }
    }
}

</script>