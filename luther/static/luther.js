function LutherMainViewModel() {
    var self = this;
    self.subdomainsURI = "http://192.168.1.8/api/v1/subdomains"; // this should be set to https
    self.userURI = "http://192.168.1.8/api/v1/user";
    self.regenURI = "http://192.168.1.8/api/v1/regen_token";
    self.refresh_interval = 600000; // ten minutes
    self.email = "";
    self.password = "";
    self.subdomains = ko.observableArray();
    self.api_errors = ko.observableArray();
    self.loggedin = ko.observable(false);
    self.new_password = ko.observable();
    self.new_password_two = ko.observable();
    self.resfreshSubs = null;

    self.ajax = function(uri, method, data) {
        var request = {
            url: uri,
            type: method,
            contentType: "application/json",
            cache: false,
            dataType: 'json',
            data: JSON.stringify(data),
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Basic "+btoa(self.email+":"+self.password));
            },
            error: function(jqXHR) {
                // debug
                if (jqXHR.responseJSON && jqXHR.responseJSON.message) {
                    var level = '';
                    if (jqXHR.status < 300) {
                        level = "alert-info";
                    } else if (jqXHR.status < 500) {
                        level = "alert-warning";
                    } else if (jqXHR.status < 600) {
                        level = "alert-danger";
                    }
                    self.api_errors.push({message: jqXHR.responseJSON.message, level: level});
                    loginViewModel.user_errors.push({message: jqXHR.responseJSON.message, level: level});
                } else if (jqXHR.message) {
                    self.api_errors.push({message: jqXHR.message});
                    loginViewModel.user_errors.push({message: jqXHR.message});
                }
            }
        }

        return $.ajax(request);
    }

    self.beginLogin = function() {
        $('#login').modal('show');
    }

    self.refreshSubdomains = function() {
        self.ajax(self.subdomainsURI, "GET").done(function(data) {
            self.loggedin(true)
            self.subdomains.removeAll()
            for (var i = 0;i<data.subdomains.length;i++) {
                self.subdomains.push({
                    update_uri: ko.observable(data.subdomains[i].GET_update_URI),
                    regen_uri: ko.observable(data.subdomains[i].regenerate_subdomain_token_URI),
                    subdomain: ko.observable(data.subdomains[i].subdomain),
                    ip: ko.observable(data.subdomains[i].ip),
                    token: ko.observable(data.subdomains[i].subdomain_token),
                    last_update: ko.observable(data.subdomains[i].last_updated+' UTC')
                });
            }
            $('#login').modal('hide');
        }).fail(function(err) {
            if (err.status == 403) {
                self.loggedin(false);
                if (!err.responseJSON || err.responseJSON.message == null) {
                    loginViewModel.user_errors.push({message: 'Invalid credentials'})
                } else if (!(err.responseJSON == null)) {
                    loginViewModel.user_errors.push({message: err.responseJSON.message})
                }
                setTimeout(self.beginLogin, 500);
            }
        });

        self.resfreshSubs = setTimeout("lutherMainViewModel.refreshSubdomains()", self.refresh_interval);
    }

    self.login = function(email, password) {
        self.email = email; 
        self.password = password;

        self.refreshSubdomains();
    }

    self.register = function(email, password, confirm_password) {
        if (self.api_errors().length) {
            self.api_errors.removeAll();
        }
        if (loginViewModel.user_errors().length) {
            loginViewModel.user_errors.removeAll();
        }
        if (password == confirm_password) {
            data = {email: email, password: password}
            self.ajax(self.userURI, 'POST', data).done(function(data) {
                self.email = email;
                self.password = password;
                if (self.api_errors().length) {
                    self.api_errors.removeAll();
                }
                if (loginViewModel.user_errors().length) {
                    loginViewModel.user_errors.removeAll();
                }
                self.refreshSubdomains();
            }).fail(function(err) {
                if (err.status == 403) {
                    if (!err.responseJSON || err.responseJSON.message == null) {
                        loginViewModel.user_errors.push({message: 'Invalid credentials'})
                    } else if (!(err.responseJSON == null)) {
                        loginViewModel.user_errors.push({message: err.responseJSON.message})
                    }
                    setTimeout(self.beginLogin, 500);
                }
            });
        } else {
            loginViewModel.user_errors.push({message: 'Passwords don\'t match.'});
            setTimeout(self.beginLogin, 500);
        }
    }

    self.beginAdd = function() {
        $('#addSub').modal('show');
    }

    self.beginUpdate = function(subdomain) {
        editSubdomainViewModel.setSubdomain(subdomain);
        $('#editSub').modal('show');
    }

    self.remove = function(subdomain) {
        data = {subdomain: subdomain.subdomain(), confirm: 'DELETE'};
        self.ajax(self.subdomainsURI, 'DELETE', data).done(function() {
            self.subdomains.remove(subdomain);
        });
    }

    self.logout = function() {
        self.email = '';
        self.password = '';
        self.loggedin(false);
        self.subdomains.removeAll();
        self.api_errors.removeAll();
        loginViewModel.user_errors.removeAll();
        clearTimeout(self.resfreshSubs);
    }

    self.beginChangePassword = function() {
        $('#editPass').modal('show');
    }

    self.changePassword = function() {
        $('#editPass').modal('hide');
        if (self.new_password() == self.new_password_two()) {
            data = {new_password: self.new_password()}
            self.ajax(self.userURI, 'PUT', data).done(function() {
                self.api_errors.push({message: 'Password changed.', level: 'alert-info'});
            });
        } else {
            self.api_errors.push({message: 'Passwords don\'t match.', level: 'alert-warning'});
        }
        self.new_password("");
        self.new_password_two("");
    }

    self.beginDelete = function() {
        $('#delUser').modal('show');
    }

    self.deleteUser = function() {
        $('#delUser').modal('hide');
        data = {'confirm':'DELETE'};
        self.ajax(self.userURI, 'DELETE', data).done(function() {
            self.subdomains.removeAll();
            self.api_errors.removeAll();
            loginViewModel.user_errors.removeAll();
            self.user = "";
            self.password = "";
            self.loggedin(false);
            clearTimeout(self.resfreshSubs);
        });
    }

    self.regenToken = function(subdomain) {
        data = {subdomain: subdomain.subdomain()}
        self.ajax(self.regenURI, 'POST', data).done(function(data) {
            var i = self.subdomains.indexOf(subdomain);
            self.subdomains()[i].update_uri(data.GET_update_URI);
            self.subdomains()[i].regen_uri(data.regenerate_subdomain_token_URI);
            self.subdomains()[i].subdomain(data.subdomain);
            self.subdomains()[i].ip(data.ip);
            self.subdomains()[i].token(data.subdomain_token);
            self.subdomains()[i].last_update(data.last_updated+' UTC');
        });
    }

    self.add = function(subdomain) {
        self.ajax(self.subdomainsURI, 'POST', subdomain).done(function(data) {
            self.subdomains.push({
                update_uri: ko.observable(data.GET_update_URI),
                regen_uri: ko.observable(data.regenerate_subdomain_token_URI),
                subdomain: ko.observable(data.subdomain),
                ip: ko.observable(data.ip),
                token: ko.observable(data.subdomain_token),
                last_update: ko.observable(data.last_updated+' UTC')
            });
        });
    }

    self.update = function(subdomain, data) {
        var endpoint = subdomain.update_uri();
        if (data.ip) {
            endpoint += '/'+data.ip;
        }
        self.ajax(endpoint, 'GET').done(function(res) {
            self.updateSubdomain(subdomain, res);
        });
    }

    self.updateSubdomain = function(subdomain, newSubdomain) {
        var i = self.subdomains.indexOf(subdomain);
        self.subdomains()[i].update_uri(newSubdomain.GET_update_URI);
        self.subdomains()[i].regen_uri(newSubdomain.regenerate_subdomain_token_URI);
        self.subdomains()[i].subdomain(newSubdomain.subdomain);
        self.subdomains()[i].ip(newSubdomain.ip);
        self.subdomains()[i].token(newSubdomain.subdomain_token);
        self.subdomains()[i].last_update(newSubdomain.last_updated+' UTC');
    }

    // self.beginLogin();
}

function AddSubdomainViewModel() {
    var self = this;
    self.subdomain = ko.observable();
    self.ip = ko.observable(luther_client_address);

    self.addSubdomain = function() {
        $('#addSub').modal('hide');

        lutherMainViewModel.add({
            subdomain: self.subdomain(),
            ip: self.ip()
        });

        self.subdomain("");
        self.ip(luther_client_address);
    }
}

function EditSubdomainViewModel() {
    var self = this;
    self.subdomain_obj = null;
    self.subdomain = ko.observable();
    self.ip = ko.observable();

    self.setSubdomain = function(subdomain) {
        self.subdomain_obj = subdomain;
        self.ip(subdomain.ip());
        self.subdomain(subdomain.subdomain());
        $('#editSub').modal('show');
    }

    self.updateSubdomain = function() {
        $('#editSub').modal('hide');

        lutherMainViewModel.update(self.subdomain_obj, {
            ip: self.ip()
        });
    }
}

function LoginViewModel() {
    var self = this;
    self.user_errors = ko.observableArray();
    self.email = ko.observable();
    self.password = ko.observable();

    self.new_email = ko.observable();
    self.new_password = ko.observable();
    self.new_password_two = ko.observable();

    self.login = function() {
        if (self.user_errors().length) {
            self.user_errors.removeAll();
        }
        if (lutherMainViewModel.api_errors().length) {
            lutherMainViewModel.api_errors.removeAll();
        }
        lutherMainViewModel.login(self.email(), self.password());
    }

    self.register = function() {
        lutherMainViewModel.register(self.new_email(), self.new_password(), self.new_password_two())
    }
}

var lutherMainViewModel = new LutherMainViewModel();
var addSubdomainViewModel = new AddSubdomainViewModel();
var editSubdomainViewModel = new EditSubdomainViewModel();
var loginViewModel = new LoginViewModel();

ko.applyBindings(lutherMainViewModel, $('#main')[0]);
ko.applyBindings(addSubdomainViewModel, $('#addSub')[0]);
ko.applyBindings(editSubdomainViewModel, $('#editSub')[0]);
ko.applyBindings(loginViewModel, $('#login')[0]);

var link = document.querySelector('link[rel="import"]');
var template = link.import.querySelector('template');
var clone = document.importNode(template.content, true);
document.querySelector('#about').appendChild(clone);

$.ajax('http://192.168.1.8/api/v1/stats', 'GET').done(function(stuff) {
    for (var i = 0; i < stuff.users.length; i++) {
        stuff.users[i][0] = Date.parse(stuff.users[i][0]);
    }
    for (var i = 0; i < stuff.subdomains.length; i++) {
        stuff.subdomains[i][0] = Date.parse(stuff.subdomains[i][0]);
    }
    for (var i = 0; i < stuff.subdomain_limit.length; i++) {
        stuff.subdomain_limit[i][0] = Date.parse(stuff.subdomain_limit[i][0]);
    }
    for (var i = 0; i < stuff.updates.length; i++) {
        stuff.updates[i][0] = Date.parse(stuff.updates[i][0]);
    }
    $('#luther-stats').highcharts({
        chart: {
            type: 'spline'
        },
        plotOptions: {
            spline: {
                marker: {
                    enabled: false
                }
            }
        },
        title: {
            text: ''
        },
        xAxis: {
            type: 'datetime',
            title: {
                text: 'Date'
            }
        },
        yAxis: {
            min: 0,
            allowDecimals: false
        },
        series: [
            {
                name: 'Number of Users',
                data: stuff.users
            },{
                name: 'Number of Subdomains',
                data: stuff.subdomains
            },{
                name: 'Number of Subdomain Updates since last check',
                data: stuff.updates
            },{
                name: 'Subdomain limit',
                data: stuff.subdomain_limit,
                dashStyle: 'longdash',
                color: '#ff0000',
                lineWidth: 1
            }
        ]
    });
});
