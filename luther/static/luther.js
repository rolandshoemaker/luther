function LutherMainViewModel() {
    var self = this;
    self.subdomainsURI = "http://192.168.1.8/api/v1/subdomains";
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
        alert('update '+subdomain.name());
    }

    self.remove = function(subdomain) {
        alert('remove '+subdomain.name());
    }

    self.ajax(self.subdomainsURI, "GET").done(function(data) {
        for (var i;i<data.subdomains.length;i++) {
            self.subdomains.push({
                update_uri: ko.observable(data.subdomains[i].GET_update_path),
                regen_uri: ko.observable(data.subdomains[i].regenerate_subdomain_token_endpoint),
                name: ko.observable(data.subdomains[i].subdomain),
                ip: ko.observable(data.subdomains[i].ip),
                token: ko.observable(data.subdomains[i].subdomain_token),
                last_update: ko.observable(data.subdomains[i].last_updated)
            });
        }
    });

    self.add = function(subdomain) {
        self.ajax(self.subdomainsURI, 'POST', subdomain).done(function(data) {
            self.subdomains.push({
                subdomain: ko.observable(data.subdomain.subdomain),
                ip: ko.observable(data.subdomain.ip)
            });
        });
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

var lutherMainViewModel = new LutherMainViewModel();
var addSubdomainViewModel = new AddSubdomainViewModel();

ko.applyBindings(lutherMainViewModel, $('#main')[0]);
ko.applyBindings(addSubdomainViewModel, $('#addSub')[0]);
