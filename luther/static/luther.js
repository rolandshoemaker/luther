function LutherMainViewModel() {
    var self = this;
    self.subdomainsURI = "http://192.168.1.8/api/v1/subdomains"; // this should be set to https
    self.email = "admin";
    self.password = "admin";
    self.subdomains = ko.observableArray();
    self.api_errors = ko.observableArray();

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
                if (jqXHR.responseJSON.message) {
                    var level = '';
                    if (jqXHR.status < 300) {
                        level = "alert-info";
                    } else if (jqXHR.status < 500) {
                        level = "alert-warning";
                    } else if (jqXHR.status < 600) {
                        level = "alert-danger";
                    }
                    self.api_errors.push({message: jqXHR.responseJSON.message, level: level});
                    console.log(jqXHR);
                } else if (jqXHR.message) {
                    self.api_errors.push({message: jqXHR.message});
                }
            }
        };

        return $.ajax(request)
    }

    self.beginAdd = function() {
        $('#addSub').modal('show');
    }

    self.beginUpdate = function(subdomain) {
        editSubdomainViewModel.setSubdomain(subdomain)
        $('#editSub').modal('show');
    }

    self.remove = function(subdomain) {
        data = {subdomain: subdomain.subdomain(), subdomain_token: subdomain.token()}
        self.ajax(self.subdomainsURI, 'DELETE', data).done(function() {
            self.subdomains.remove(subdomain);
        });
    }

    self.regenToken = function(subdomain) {
        self.ajax(subdomain.regen_uri(), 'POST').done(function(data) {
            var i = self.subdomains.indexOf(subdomain);
            self.subdomains()[i].update_uri(data.GET_update_endpoint);
            self.subdomains()[i].regen_uri(data.regenerate_subdomain_token_endpoint);
            self.subdomains()[i].subdomain(data.subdomain);
            self.subdomains()[i].ip(data.ip);
            self.subdomains()[i].token(data.subdomain_token);
            self.subdomains()[i].last_update(data.last_updated);
        });
    }

    self.ajax(self.subdomainsURI, "GET").done(function(data) {
        for (var i = 0;i<data.subdomains.length;i++) {
            self.subdomains.push({
                update_uri: ko.observable(data.subdomains[i].GET_update_endpoint),
                regen_uri: ko.observable(data.subdomains[i].regenerate_subdomain_token_endpoint),
                subdomain: ko.observable(data.subdomains[i].subdomain),
                ip: ko.observable(data.subdomains[i].ip),
                token: ko.observable(data.subdomains[i].subdomain_token),
                last_update: ko.observable(data.subdomains[i].last_updated)
            });
        }
    });

    self.add = function(subdomain) {
        self.ajax(self.subdomainsURI, 'POST', subdomain).done(function(data) {
            self.subdomains.push({
                update_uri: ko.observable(data.subdomain.GET_update_endpoint),
                regen_uri: ko.observable(data.subdomain.regenerate_subdomain_token_endpoint),
                subdomain: ko.observable(data.subdomain.subdomain),
                ip: ko.observable(data.subdomain.ip),
                token: ko.observable(data.subdomain.subdomain_token),
                last_update: ko.observable(data.subdomain.last_updated)
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
        self.subdomains()[i].update_uri(newSubdomain.GET_update_endpoint);
        self.subdomains()[i].regen_uri(newSubdomain.regenerate_subdomain_token_endpoint);
        self.subdomains()[i].subdomain(newSubdomain.subdomain);
        self.subdomains()[i].ip(newSubdomain.ip);
        self.subdomains()[i].token(newSubdomain.subdomain_token);
        self.subdomains()[i].last_update(newSubdomain.last_updated);
    }
}

function AddSubdomainViewModel() {
    var self = this;
    self.subdomain = ko.observable();
    self.ip = ko.observable();

    self.addSubdomain = function() {
        $('#addSub').modal('hide');

        lutherMainViewModel.add({
            subdomain: self.subdomain(),
            ip: self.ip()
        });

        self.subdomain("");
        self.ip("");
    }
}

function EditSubdomainViewModel() {
    var self = this;
    self.subdomain_obj = null;
    self.subdomain = ko.observable();
    self.ip = ko.observable();

    self.setSubdomain = function(subdomain) {
        self.subdomain_obj = subdomain;
        self.subdomain(subdomain.subdomain());
        self.ip(subdomain.ip());
        $('#editSub').modal('show');
    }

    self.updateSubdomain = function() {
        $('#editSub').modal('hide');

        lutherMainViewModel.update(self.subdomain_obj, {
            ip: self.ip()
        });
    }
}

var lutherMainViewModel = new LutherMainViewModel();
var addSubdomainViewModel = new AddSubdomainViewModel();
var editSubdomainViewModel = new EditSubdomainViewModel();

ko.applyBindings(lutherMainViewModel, $('#main')[0]);
ko.applyBindings(addSubdomainViewModel, $('#addSub')[0]);
ko.applyBindings(editSubdomainViewModel, $('#editSub')[0]);
