function LutherMainViewModel() {
    var self = this;
    self.baseURI = "http://192.168.1.8";
    self.subdomainsURI = self.baseURI+"/api/v1/subdomains"; // this should be set to https
    self.userURI = self.baseURI+"/api/v1/user";
    self.regenURI = self.baseURI+"/api/v1/regen_token";
    self.ipURI = self.baseURI+"/api/v1/guess_ip";
    self.refresh_interval = 600000; // ten minutes
    self.email = ko.observable();
    self.password = ko.observable();
    self.subdomains = ko.observableArray();
    self.api_errors = ko.observableArray();
    self.loggedin = ko.observable(false);
    self.new_password = ko.observable();
    self.new_password_two = ko.observable();
    self.resfreshSubs = null;
    self.singleSubdomain = ko.observable('');
    self.singleToken = ko.observable('');
    self.getIP = function() {
        var ip = null;
        $.ajax({
            type: 'GET',
            url: self.ipURI,
            async: false,
            success: function(data) {
                ip = data.guessed_ip;
            }
        });
        return ip;
    }
    self.user_ip = self.getIP()
    self.singleIP = ko.observable(self.user_ip);

    self.ajax = function(uri, method, data) {
        var request = {
            url: uri,
            type: method,
            contentType: "application/json",
            cache: false,
            dataType: 'json',
            data: JSON.stringify(data),
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Basic "+btoa(self.email()+":"+self.password()));
            },
            error: function(jqXHR) {
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
                } else if (jqXHR.message) {
                    self.api_errors.push({message: jqXHR.message, level: 'alert-danger'});
                }
            }
        }

        return $.ajax(request);
    }

    self.singleTokenUpdate = function() {
        if (self.singleSubdomain() == '' || self.singleToken == '') {
            self.api_errors.push({message: 'Both subdomain name and subdomain_token are required', level: 'alert-danger'});
            return false;
        }
        var user_ip = '';
        if (self.singleIP() == '') {
            user_ip = self.getIP();
            self.user_ip = user_ip;
            self.singleIP(user_ip);
        }
        $.get(self.subdomainsURI+'/'+self.singleSubdomain()+'/'+self.singleToken()+'/'+self.singleIP()).done(function(data) {
            self.api_errors.push({message: data.message, level: 'alert-success'});
            self.singleSubdomain('');
            self.singleToken('');
            self.singleIP(self.user_ip);
        }).fail(function(err) {
            if (err.responseJSON && err.responseJSON.message) {
                    var level = '';
                    if (err.status < 300) {
                        level = "alert-info";
                    } else if (err.status < 500) {
                        level = "alert-warning";
                    } else if (err.status < 600) {
                        level = "alert-danger";
                    }
                    self.api_errors.push({message: err.responseJSON.message, level: level});
                } else if (err.message) {
                    self.api_errors.push({message: err.message, level: 'alert-danger'});
                }
        });
    }

    self.beginLogin = function() {
        $('#login').modal('show');
    }

    self.refreshSubdomains = function() {
        $('#refreshSpin').addClass('fa-spin');
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
            $('#refreshSpin').removeClass('fa-spin');
        }).fail(function(err) {
            if (err.status == 403) {
                self.loggedin(false);
                if (!err.responseJSON || err.responseJSON.message == null) {
                    self.api_errors.push({message: 'Invalid credentials', level: 'alert-danger'})
                } else if (!(err.responseJSON == null)) {
                    self.api_errors.push({message: err.responseJSON.message, level: 'alert-danger'})
                }
            }
            $('#refreshSpin').removeClass('fa-spin');
        });

    }

    self.subTimeout = function () {
        self.refreshSubdomains();
        self.resfreshSubs = setTimeout("lutherMainViewModel.subTimeout()", self.refresh_interval);
    }

    self.startLogin = function() {
        if (self.api_errors().length) {
            self.api_errors.removeAll();
        }
        self.login(self.email(), self.password());
    }

    self.login = function(email, password) {
        self.email(email); 
        self.password(password);

        self.subTimeout();
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
                if (self.api_errors().length) {
                    self.api_errors.removeAll();
                }
                if (loginViewModel.user_errors().length) {
                    loginViewModel.user_errors.removeAll();
                }
                self.login(email, password);
            }).fail(function(err) {
                if (err.status == 403) {
                    if (!err.responseJSON || err.responseJSON.message == null) {
                        self.api_errors.push({message: 'Invalid credentials', level: 'alert-danger'})
                    } else if (!(err.responseJSON == null)) {
                        self.api_errors.push({message: err.responseJSON.message, level: 'alert-danger'})
                    }
                }
            });
        } else {
            self.api_errors.push({message: 'Passwords don\'t match.', level: 'alert-danger'});
        }
    }

    self.beginAdd = function() {
        $('#addSub').modal('show');
    }

    self.beginUpdate = function(subdomain) {
        editSubdomainViewModel.setSubdomain(subdomain);
        $('#editSub').modal('show');
    }

    self.beginRemove = function(subdomain) {
        delSubdomainViewModel.setSubdomain(subdomain);
        $('#delSub').modal('show');
    }

    self.logout = function() {
        self.email('');
        self.password('');
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
                self.api_errors.push({message: 'Password changed.', level: 'alert-success'});
                self.password(self.new_password());
            });
        } else {
            self.api_errors.push({message: 'Passwords don\'t match.', level: 'alert-danger'});
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

    self.remove = function(subdomain_obj, subdomain) {
        data = {subdomain: subdomain, confirm: 'DELETE'};
        self.ajax(self.subdomainsURI, 'DELETE', data).done(function() {
            lutherMainViewModel.subdomains.remove(subdomain_obj);
            lutherMainViewModel.api_errors.push({message: '\''+subdomain+'\' has been deleted', level: 'alert-success'});
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
}

function AddSubdomainViewModel() {
    var self = this;
    self.subdomain = ko.observable();
    self.ip = ko.observable(lutherMainViewModel.user_ip);
    self.user_ip = ko.observable(self.ip());

    self.addSubdomain = function() {
        $('#addSub').modal('hide');

        lutherMainViewModel.add({
            subdomain: self.subdomain(),
            ip: self.ip()
        });

        self.subdomain("");
        self.ip(lutherMainViewModel.user_ip);
    }
}

function EditSubdomainViewModel() {
    var self = this;
    self.subdomain_obj = null;
    self.subdomain = ko.observable();
    self.ip = ko.observable();
    self.user_ip = ko.observable(lutherMainViewModel.user_ip);

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

function DelSubdomainViewModel() {
    var self = this;
    self.subdomain_obj = null;
    self.subdomain = ko.observable();

    self.setSubdomain = function(subdomain) {
        self.subdomain_obj = subdomain;
        self.subdomain(subdomain.subdomain());
    }

    self.remove = function() {
        $('#delSub').modal('hide');
        lutherMainViewModel.remove(self.subdomain_obj, self.subdomain());
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
        lutherMainViewModel.register(self.new_email(), self.new_password(), self.new_password_two());
        $('#login').modal('hide');
    }
}

var lutherMainViewModel = new LutherMainViewModel();
var addSubdomainViewModel = new AddSubdomainViewModel();
var editSubdomainViewModel = new EditSubdomainViewModel();
var delSubdomainViewModel = new DelSubdomainViewModel();
var loginViewModel = new LoginViewModel();

ko.applyBindings(lutherMainViewModel, $('#main')[0]);
ko.applyBindings(addSubdomainViewModel, $('#addSub')[0]);
ko.applyBindings(editSubdomainViewModel, $('#editSub')[0]);
ko.applyBindings(delSubdomainViewModel, $('#delSub')[0]);
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
            type: 'spline',
            renderTo: '#luther-stats'
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
                data: stuff.users,
                states: {
                    hover: {
                        enabled: false
                    }
                }
            },{
                name: 'Number of Subdomains',
                data: stuff.subdomains,
                states: {
                    hover: {
                        enabled: false
                    }
                }
            },{
                name: 'Number of Subdomain updates since last check',
                data: stuff.updates,
                states: {
                    hover: {
                        enabled: false
                    }
                }
            },{
                name: 'dnsd.co Subdomain limit',
                data: stuff.subdomain_limit,
                dashStyle: 'longdash',
                color: '#ff0000',
                lineWidth: 1,
                visible: false,
                states: {
                    hover: {
                        enabled: false
                    }
                }
            }
        ],
        tooltip: {
            enabled: false
        }
    });
});

var width = $('.justified').width();
$('.justified').css('margin-left', '-' + (width / 2)+'px');

$('#accordion').on('shown.bs.collapse', function () {
    $(window).resize();
});
