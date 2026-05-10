<script lang="ts" setup>
import { reactive } from "vue";
import type { User } from "~/models/user";
const { createAccount } = useUsers();

const form: User = reactive({
    firstName: "",
    lastName: "",
    email: "",
    password: "",
});

const validationError = ref("");

const getPasswordRequirements = () => {
    const missing = [];
    if (form.password.length < 8) missing.push("8+ characters");
    if (!/[A-Z]/.test(form.password)) missing.push("uppercase");
    if (!/\d/.test(form.password)) missing.push("number");
    if (!/[!@#$%&?]/.test(form.password)) missing.push("special character");
    return missing;
};

watch(
    () => form.password,
    () => {
        if (
            validationError.value &&
            !validationError.value.includes("Server error")
        ) {
            const missing = getPasswordRequirements();

            if (missing.length === 0) {
                validationError.value = "";
            } else {
                validationError.value =
                    "Password needs: " + missing.join(", ") + ".";
            }
        }
    },
);

const handleSubmit = async () => {
    const missing = getPasswordRequirements();
    if (missing.length > 0) {
        validationError.value = "Password needs: " + missing.join(", ") + ".";
        return;
    }

    try {
        await createAccount({
            firstName: form.firstName,
            lastName: form.lastName,
            email: form.email,
            password: form.password,
        });

        Object.assign(form, {
            firstName: "",
            lastName: "",
            email: "",
            password: "",
        });

        validationError.value = "";
    } catch (e: any) {
        console.error("Singup Failed: ", e);
        validationError.value = "Server error. Please try again.";
    }
};
</script>

<template>
    <section class="section">
        <RadialGradient
            :size="1500"
            :position-x="-50"
            :position-y="40"
            :bottom="0"
            :left="0"
            :opacity="1"
        />

        <RadialGradient
            :size="800"
            :position-x="65"
            :position-y="45"
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
                            required
                        />

                        <input
                            v-model="form.lastName"
                            type="text"
                            id="last-name"
                            placeholder="Last Name"
                            required
                        />
                    </div>

                    <input
                        v-model="form.email"
                        type="email"
                        id="email"
                        placeholder="Email"
                        required
                    />

                    <div class="password-input">
                        <input
                            v-model="form.password"
                            type="password"
                            id="password"
                            placeholder="Password"
                            required
                        />

                        <p v-if="validationError" class="validation-msg">
                            {{ validationError }}
                        </p>
                    </div>
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

<style lang="scss" scoped src="~/assets/scss/pages/SignUp.scss"></style>
