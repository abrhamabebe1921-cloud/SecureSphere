document.addEventListener('DOMContentLoaded', () => {
    if (window.location.hash) {
        if (window.location.hash === '#usersPanel') toggleUsersPanel();
        if (window.location.hash === '#trainingPanel') toggleTrainingPanel();
    }
});
