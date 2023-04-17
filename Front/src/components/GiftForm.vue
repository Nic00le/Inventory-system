<template>
    <form @submit.prevent="submitRecords">
        <div class="row">
            <div class="form-group col-md-6">
                <label for="inputEmail4">Title</label>
                <input type="text" class="form-control" id="Title" v-model="records.title">
            </div>
            <div class="form-group col-md-6">
                <label for="inputPassword4">Category</label>
                <select id="Category" class="form-control" v-model="records.category">
                    <option selected>Open this select menu</option>
                    <option value="Cakes">Cakes</option>
                    <option value="Flowers">Flowers</option>
                    <option value="PersonalizedGifts">Personalized Gifts</option>
                    <option value="toys">toys</option>
                </select>
            </div>
        </div>
        <div class="row">
            <div class="form-group col-md-6">
                <label for="inputPassword4">Image</label>
                <input type="text" class="form-control" id="Image" v-model="records.image">
            </div>
            <div class="form-group col-md-3">
                <label for="inputEmail4">Amount</label>
                <input type="number" class="form-control" id="Amount" v-model="records.quantity">
            </div>
            <div class="form-group col-md-3">
                <label for="inputEmail4">Unit Price (HKD)</label>
                <input type="number" class="form-control" id="Price" v-model="records.price">
            </div>
        </div>
        <div class="row">
            <div class="form-group col-md-6">
                <label for="inputEmail4">Donated by</label>
                <input type="text" class="form-control" id="DonatedBy" v-model="records.donated_by">
            </div>
            <div class="form-group col-md-6">
                <label for="inputPassword4">Location</label>
                <input type="text" class="form-control" id="Location" v-model="records.location">
            </div>
        </div>
        <div class="row">
            <div class="form-group col-md-6">
                <label for="inputEmail4">Descriptions</label>
                <input type="text" class="form-control" id="Descriptions"
                    v-model="records.descriptions">
            </div>
            <div class="form-group col-md-6">
                <label for="inputPassword4">Address 2</label>
                <input type="text" class="form-control" id="Remarks" v-model="records.address">
            </div>
        </div>
        <button v-if="newRecord == true" type="submit" class="btn btn-primary">Save</button>
    </form>
    <div v-if="$route.params.id"> 
        <button @click.prevent="updateRecords" class="btn btn-primary">Save</button> 
        <button @click.prevent="deleteRecords" class="btn btn-danger">Delete</button> 
    </div> 
</template>

<script>
import { ref, onMounted} from "vue";

export default {
    name: 'GiftForm',
    props:{
        id: String,
        newRecord: Boolean
    },
    setup(props) {
        // var url = window.location.href;
        // var array = url.split('/');
        // var type = array[array.length - 2];

        const records = ref({});

        onMounted(async () => {
            if (props.id) {
                var response = await fetch("/api/records/" + props.id)

                if (response.ok) {
                    records.value = await response.json();
                }
            }
        });
        

        const submitRecords = async function () {
            records.value.type = "gifts"

            // event.preventDefault();

            var response = await fetch("/api/gift/detail/", {
                method: "post",
                headers: {
                    // 'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Type': 'application/json'
                },

                // body: new URLSearchParams(new FormData(event.target))
                body: JSON.stringify(records.value)
            });
            console.log(records.value)
            if (response.ok) {

                var text = await response.text();
                alert(text);
                // location.assign("/bookings")
            } else {
                alert(response.statusText)
            }

        }

        const updateRecords = async function () {
            delete records.value._id;

            var response = await fetch("/api/record/update/" + props.id, {
                method: "put",
                headers: {
                    // 'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Type': 'application/json'
                },

                // body: new URLSearchParams(new FormData(event.target))
                body: JSON.stringify(records.value)
            });
            console.log(records.value)
            if (response.ok) {

                var text = await response.text();
                alert(text);
                // location.assign("/bookings")
            } else {
                alert(response.statusText)
            }
        }

        const deleteRecords = async function () {

            var response = await fetch("/api/record/delete/" + props.id , {
                method: "delete",
                headers: {
                    // 'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Type': 'application/json'
                }

                // body: new URLSearchParams(new FormData(event.target))
                // body: JSON.stringify(records.value)
            });
            if (response.ok) {

                // var text = await response.text();
                alert("Booking is deleted");
                // location.assign("/bookings")
            } else {
                alert(response.statusText)
            }
        }

        return {
            submitRecords,
            deleteRecords,
            updateRecords,
            records
        }
    }
}
</script>