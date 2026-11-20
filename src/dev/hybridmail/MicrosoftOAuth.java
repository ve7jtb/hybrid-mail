package dev.hybridmail;

import com.google.gson.*;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;

/** Microsoft Desktop authorization-code flow: system browser, loopback and S256 PKCE. */
public final class MicrosoftOAuth {
    // Public installed-app registration. This is not a confidential server credential.
    // User access/refresh tokens remain separate in the operating-system credential store.
    static Client bundledClient()throws IOException{
        return new Client("a8ec73d4-2c8c-465b-9570-6cbe34857fab");
    }
    static final String READ_SCOPE="https://graph.microsoft.com/Mail.Read";
    static final String SEND_SCOPE="https://graph.microsoft.com/Mail.Send";
    static final String SCOPE=READ_SCOPE+" "+SEND_SCOPE+" https://graph.microsoft.com/User.Read offline_access";
    static final URI AUTH=URI.create("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize");
    static final URI TOKEN=URI.create("https://login.microsoftonline.com/consumers/oauth2/v2.0/token");
    public record Client(String id){
        public Client{if(id==null||!id.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"))throw new IllegalArgumentException("Enter the Microsoft application (client) ID, a UUID");}
        public String toString(){return "Microsoft public desktop OAuth client";}
    }
    public static final class Token implements AutoCloseable{
        private char[] value;private char[] refresh;private final Instant expires;
        Token(String value,long seconds){this.value=value.toCharArray();expires=Instant.now().plusSeconds(Math.max(0,seconds-60));}
        synchronized String refreshToken(){return refresh==null?null:new String(refresh);}
        public synchronized boolean valid(){return value!=null&&Instant.now().isBefore(expires);}
        public synchronized char[] credential()throws IOException{if(!valid())throw new IOException("Microsoft sign-in expired. Sign in again.");return value.clone();}
        public synchronized void close(){if(value!=null)Arrays.fill(value,'\0');value=null;if(refresh!=null)Arrays.fill(refresh,'\0');refresh=null;}
        public String toString(){return "Microsoft OAuth session token (redacted)";}
    }
    static String random(){byte[] bytes=new byte[32];new SecureRandom().nextBytes(bytes);return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
    static String challenge(String verifier)throws Exception{return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));}
    static String form(Map<String,String> fields){return fields.entrySet().stream().map(e->URLEncoder.encode(e.getKey(),StandardCharsets.UTF_8)+"="+URLEncoder.encode(e.getValue(),StandardCharsets.UTF_8)).collect(java.util.stream.Collectors.joining("&"));}
    static Map<String,String> query(String query)throws IOException{
        Map<String,String> fields=new HashMap<>();if(query==null||query.length()>16384)throw new IOException("Invalid OAuth callback");
        try{for(String part:query.split("&")){String[] pair=part.split("=",2);String key=URLDecoder.decode(pair[0],StandardCharsets.UTF_8);String value=pair.length==2?URLDecoder.decode(pair[1],StandardCharsets.UTF_8):"";if(fields.putIfAbsent(key,value)!=null)throw new IOException("Duplicate OAuth callback parameter");}}catch(IllegalArgumentException e){throw new IOException("Invalid OAuth callback");}
        return fields;
    }
    static String code(String query,String expected)throws IOException{
        var fields=query(query);String actual=fields.get("state");
        if(actual==null||!MessageDigest.isEqual(actual.getBytes(StandardCharsets.UTF_8),expected.getBytes(StandardCharsets.UTF_8)))throw new IOException("OAuth response state did not match");
        if(fields.containsKey("error"))throw new IOException("Microsoft sign-in was denied or cancelled");
        String code=fields.get("code");if(code==null||code.isBlank())throw new IOException("Missing Microsoft authorization code");return code;
    }
    static URI authorization(Client client,String email,String redirect,String state,String verifier)throws Exception{
        Map<String,String> p=new LinkedHashMap<>();p.put("client_id",client.id());p.put("redirect_uri",redirect);p.put("response_type","code");p.put("scope",SCOPE);p.put("state",state);p.put("code_challenge",challenge(verifier));p.put("code_challenge_method","S256");p.put("login_hint",email);p.put("prompt","select_account");return URI.create(AUTH+"?"+form(p));
    }
    public static Token authorize(Client client,String email,Consumer<URI> browser,BooleanSupplier cancelled)throws Exception{
        String state=random(),verifier=random();CompletableFuture<String> response=new CompletableFuture<>();
        HttpServer server=HttpServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),0),0);
        String redirect="http://localhost:"+server.getAddress().getPort()+"/";
        server.createContext("/",exchange->{
            int status=400;String message="Sign-in was not completed. Return to PQ Mail.";
            try{
                if(!exchange.getRequestMethod().equals("GET")||!exchange.getRequestURI().getPath().equals("/"))throw new IOException("Invalid callback");
                String callbackCode=code(exchange.getRequestURI().getRawQuery(),state);
                if(response.complete(callbackCode)){status=200;message="Microsoft authorization received. You can close this window and return to PQ Mail.";}
            }catch(IOException e){
                // A mismatched or malformed callback must not abort the legitimate browser flow.
                try{var fields=query(exchange.getRequestURI().getRawQuery());if(state.equals(fields.get("state"))&&fields.containsKey("error"))response.completeExceptionally(new IOException("Microsoft sign-in was denied or cancelled"));}catch(Exception ignored){}
            }
            byte[] bytes=message.getBytes(StandardCharsets.UTF_8);exchange.getResponseHeaders().set("Content-Type","text/plain; charset=utf-8");exchange.getResponseHeaders().set("Cache-Control","no-store");exchange.getResponseHeaders().set("Content-Security-Policy","default-src 'none'");exchange.sendResponseHeaders(status,bytes.length);try(var out=exchange.getResponseBody()){out.write(bytes);}finally{exchange.close();}
        });
        server.start();
        try{
            browser.accept(authorization(client,email,redirect,state,verifier));
            long deadline=System.nanoTime()+TimeUnit.MINUTES.toNanos(3);String authCode;
            while(true){if(cancelled.getAsBoolean())throw new IOException("Microsoft sign-in cancelled");if(System.nanoTime()>deadline)throw new IOException("Microsoft sign-in timed out. Try again.");try{authCode=response.get(250,TimeUnit.MILLISECONDS);break;}catch(TimeoutException wait){}catch(ExecutionException e){throw new IOException("Microsoft sign-in was denied or cancelled");}}
            if(cancelled.getAsBoolean())throw new IOException("Microsoft sign-in cancelled");
            Map<String,String> params=new LinkedHashMap<>();params.put("client_id",client.id());params.put("code",authCode);params.put("code_verifier",verifier);params.put("redirect_uri",redirect);params.put("scope",SCOPE);params.put("grant_type","authorization_code");
            Token token=exchange(params);if(cancelled.getAsBoolean()){token.close();throw new IOException("Microsoft sign-in cancelled");}return token;
        }finally{server.stop(0);response.cancel(true);}
    }
    static Map<String,String> refreshParameters(Client client,String refresh)throws IOException{
        if(refresh==null||refresh.isBlank()||refresh.length()>16384)throw new IOException("Invalid saved Microsoft refresh token");
        Map<String,String> params=new LinkedHashMap<>();params.put("client_id",client.id());params.put("scope",SCOPE);params.put("grant_type","refresh_token");params.put("refresh_token",refresh);return params;
    }
    static Token refresh(Client client,String refresh)throws Exception{
        Token token=exchange(refreshParameters(client,refresh));if(token.refresh==null)token.refresh=refresh.toCharArray();return token;
    }
    private static Token exchange(Map<String,String> params)throws Exception{
        HttpClient http=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).followRedirects(HttpClient.Redirect.NEVER).build();
        HttpRequest request=HttpRequest.newBuilder(TOKEN).timeout(Duration.ofSeconds(30)).header("Content-Type","application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(form(params))).build();
        HttpResponse<InputStream> result=http.send(request,HttpResponse.BodyHandlers.ofInputStream());
        try(InputStream in=result.body()){
            byte[] bytes=in.readNBytes(65537);try{
                if(bytes.length>65536)throw new IOException("Microsoft token response too large");
                if(result.statusCode()!=200)throw new IOException("Microsoft token request failed (HTTP "+result.statusCode()+"). If access expired or was revoked, sign in again; otherwise check your connection and retry.");
                return token(new String(bytes,StandardCharsets.UTF_8));
            }finally{Arrays.fill(bytes,(byte)0);}
        }
    }
    static boolean granted(String scope){
        var grants=new HashSet<String>();for(String entry:scope.split(" "))grants.add(entry.replace("https://graph.microsoft.com/",""));
        return grants.containsAll(List.of("Mail.Read","Mail.Send","User.Read"));
    }
    static Token token(String json)throws IOException{
        try{JsonObject data=JsonParser.parseString(json).getAsJsonObject();String value=data.get("access_token").getAsString();long seconds=data.get("expires_in").getAsLong();
            if(!"Bearer".equalsIgnoreCase(data.get("token_type").getAsString())||value.isBlank()||seconds<=0||seconds>86400)throw new IOException("Invalid Microsoft token response");
            if(!data.has("scope")||!granted(data.get("scope").getAsString()))throw new IOException("Microsoft did not grant the mail permission");
            Token token=new Token(value,seconds);if(data.has("refresh_token")){String refresh=data.get("refresh_token").getAsString();if(refresh.isBlank()||refresh.length()>16384)throw new IOException("Invalid refresh token");token.refresh=refresh.toCharArray();}return token;
        }catch(IOException e){throw e;}catch(RuntimeException e){throw new IOException("Invalid Microsoft token response");}
    }
}
