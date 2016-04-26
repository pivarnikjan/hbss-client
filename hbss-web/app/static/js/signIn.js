/**
 * Created by pivar on 4/27/2016.
 */
$(function () {
    $('#btnSignIn1').click(function () {

        $.ajax({
            url: '/validateLogin',
            data: $('form').serialize(),
            type: 'POST',
            success: function (response) {
                console.log(response);
            },
            error: function (error) {
                console.log(error);
            }
        });
    });
});