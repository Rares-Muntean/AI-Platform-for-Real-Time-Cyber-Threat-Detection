<script lang="ts" setup>
import { reactive } from "vue";

const form = reactive({
    firstName: "",
    lastName: "",
    email: "",
    password: "",
});

const handleSubmit = () => {
    console.log("Form Submitted:", form);
};
</script>

<template>
    <section class="section">
        <RadialGradient
            :size="1300"
            :position-x="-50"
            :position-y="40"
            :bottom="0"
            :left="0"
        />

        <RadialGradient
            :size="800"
            :position-x="65"
            :position-y="40"
            :bottom="0"
            :right="0"
        />

        <div class="signup-container">
            <div class="logo-wrapper">
                <div class="logo-container">
                    <img class="logo-icon" src="/images/logo-icon.png" />
                    <p class="icon-text">VELOX</p>
                </div>

                <Separator />
            </div>

            <div class="heading-wrapper">
                <h1 class="title">Create an account</h1>
                <p class="description">
                    Start securing your devices with ease.
                </p>
            </div>

            <form action="" @submit.prevent="handleSubmit">
                <div class="input-wrapper">
                    <div class="full-name">
                        <input
                            v-model="form.firstName"
                            type="text"
                            id="first-name"
                            placeholder="First Name"
                        />

                        <input
                            v-model="form.lastName"
                            type="text"
                            id="last-name"
                            placeholder="Last Name"
                        />
                    </div>

                    <input
                        v-model="form.email"
                        type="text"
                        id="email"
                        placeholder="Email"
                    />
                    <input
                        v-model="form.password"
                        type="text"
                        id="password"
                        placeholder="Password"
                    />
                </div>

                <button type="submit" class="btn-primary stretched btn-signup">
                    Create account
                </button>
            </form>

            <p class="login-redirect">
                Already have an account? <a href="#">Log in</a>
            </p>
        </div>
    </section>
</template>

<style lang="scss" src="~/assets/scss/scoped/SignUp.scss"></style>
