library oauth1_client;

import 'dart:async';

import 'package:http/http.dart' as http;

import 'authorization_header_builder.dart';
import 'client_credentials.dart';
import 'credentials.dart';
import 'signature_method.dart';

/// A proxy class describing OAuth 1.0 Authenticated Request
/// http://tools.ietf.org/html/rfc5849#section-3
///
/// If _credentials is null, this is usable for authorization requests too.
class Client extends http.BaseClient {
  final SignatureMethod _signatureMethod;
  final ClientCredentials _clientCredentials;
  final Credentials _credentials;
  final http.BaseClient _httpClient;

  /// OAuth signature is invalid when there are empty query parameters in the request URL
  ///
  /// When this workaround is enabled (which is default), incoming request (of type [http.Request]) with empty query
  /// parameters are fixed.
  final bool skipsEmptyQueryParameters;

  /// A constructor of Client.
  ///
  /// If you want to use in web browser, pass http.BrowserClient object for httpClient.
  /// https://api.dartlang.org/apidocs/channels/stable/dartdoc-viewer/http/http-browser_client.BrowserClient
  Client(
    this._signatureMethod,
    this._clientCredentials,
    this._credentials, {
    this.skipsEmptyQueryParameters = true,
    http.BaseClient? httpClient,
  }) : _httpClient = httpClient != null ? httpClient : http.Client() as http.BaseClient;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    final http.BaseRequest cleanRequest;
    if (skipsEmptyQueryParameters && request is http.Request) {
      final Map<String, String> cleanQueryParams = <String, String>{...request.url.queryParameters}
        ..removeWhere((String key, String value) => value.isEmpty);
      final Uri cleanUri = request.url.replace(queryParameters: cleanQueryParams);

      final http.Request r = http.Request(request.method, cleanUri);

      // Duplicate BaseRequest settings
      r.headers.addAll(request.headers);
      r.persistentConnection = request.persistentConnection;
      r.followRedirects = request.followRedirects;
      r.maxRedirects = request.maxRedirects;

      // Duplicate Request settings
      r.encoding = request.encoding;
      r.body = request.body;

      cleanRequest = r;
    } else {
      cleanRequest = request;
    }

    final AuthorizationHeaderBuilder ahb = AuthorizationHeaderBuilder();
    ahb.signatureMethod = _signatureMethod;
    ahb.clientCredentials = _clientCredentials;
    ahb.credentials = _credentials;
    ahb.method = cleanRequest.method;
    ahb.url = cleanRequest.url.toString();
    final Map<String, String> headers = cleanRequest.headers;
    Map<String, String> additionalParameters = <String, String>{};
    if (headers.containsKey('Authorization')) {
      additionalParameters = Uri.splitQueryString(headers['Authorization']!);
    }
    if (headers.containsKey('content-type') && headers['content-type']!.contains('application/x-www-form-urlencoded')) {
      additionalParameters.addAll(Uri.splitQueryString((cleanRequest as http.Request).body));
    }
    ahb.additionalParameters = additionalParameters;

    cleanRequest.headers['Authorization'] = ahb.build().toString();
    return _httpClient.send(cleanRequest);
  }
}
