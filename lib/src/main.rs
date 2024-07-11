use std::env;
use std::{collections::{HashSet, HashMap}};

use futures::StreamExt;
use telegram_bot::*;
use dotenv::dotenv;

use regex::*;
use lazy_static::lazy_static;
use chrono::{Datelike};

use google_youtube3 as youtube3;
use youtube3::api::{Playlist, PrivacyStatus, PlaylistWithSet, PlaylistItem, VideoWithTgData};
#[allow(unused_imports)]
use youtube3::{Result, Error};
use youtube3::{YouTube, oauth2, hyper, chrono};
use yup_oauth2::hyper_rustls as hyper_rustls;

use yup_oauth2::hyper_rustls::HttpsConnector;
use hyper::client::HttpConnector;
use hyper::client::connect::dns::GaiResolver;

static CHANNEL_ID: &str = "";
static NUM_OF_PLAYLISTS: u32 = 55;
//ako nema problema s memorijom, provjeri kolko API poziva moš napravit tjedno/mjesečno
//pa izračunaj kolko puta se playlista moze updateat a da ljudi mogu poslat 200 videa dnevno

//async fn main() -> Result<(), telegram_bot::errors::Error>{
#[tokio::main]
async fn main() -> Result<()> {
        #![allow(unused_variables)]
        println!("VVTTV bot");
        dotenv().ok();
        let token = env::var("TELEGRAM_BOT_TOKEN").expect("TELEGRAM_BOT_TOKEN not set");
        let api = Api::new(token);
        let mut stream = api.stream();
        lazy_static! {
                //todo dodaj da je cijeli yt link jedan group, pa da moš cijeli link extractat. onda to dodaj dole u message kad nemre nać video.
                //nazovi grupu link
                //neš u stilu r"(?P<yt_link>((?:https?:)?//)?((?:www|m)\.)?((?:youtube(-nocookie)?\.com|youtu\.be))(/(?:[\w\-]+\?v=|embed/|v/)?)(?P<video_id>[\w\-]+)(\S+)?)"
                static ref YT_LINK_REGEX: Regex = Regex::new(r"(?P<yt_link>((?:https?:)?//)?((?:www|m)\.)?((?:youtube(-nocookie)?\.com|youtu\.be))(/(?:[\w\-]+\?v=|embed/|v/)?)(?P<video_id>[\w\-]+)(\S+)?)").unwrap();
            }
        let secret = yup_oauth2::read_application_secret("client_secret_209926296898-vf9lmfua5ss1u4kk1j3dkj4tao24124i.apps.googleusercontent.com.json")
                .await
                .unwrap();
        let auth = oauth2::InstalledFlowAuthenticator::builder(
                secret,
                oauth2::InstalledFlowReturnMethod::Interactive,)
                .persist_tokens_to_disk("vvttv_token.json")
                .build()
                .await
                .unwrap();
        let scopes = &[ "https://www.googleapis.com/auth/youtubepartner",
                        "https://www.googleapis.com/auth/youtube",
                        "https://www.googleapis.com/auth/youtube.force-ssl"
                        ];

        match auth.token(scopes).await {
                Err(e) => println!("error u .token: {:?}", e),
                Ok(t) => println!("The token is\n{:?}\n", t),
        }

        let hub = YouTube::new(hyper::Client::builder()
                .build(hyper_rustls::HttpsConnectorBuilder::new()
                        .with_native_roots()
                        .https_or_http()
                        .enable_http1()
                        .enable_http2()
                        .build()), auth);

        /* --------- NAPRAVI INICIJALNI HASHMAP PLAYLISTA --------- */
        let mut playlist_hashmap: HashMap<String, PlaylistWithSet> = HashMap::new();
        let mut all_videos: HashSet<String> = HashSet::new();

        println!("sve plejliste");
        fetch_playlists_from_yt(&hub, &mut playlist_hashmap, &mut all_videos, NUM_OF_PLAYLISTS, CHANNEL_ID).await.expect("to fetch youtube playlists");
        println!("----------------------------");
        println!("hashmap je");
        for (k,v) in &playlist_hashmap {
                println!("k: {}\t\t\tv: {:?}", k, v.playlist_name);
        }

        // stream može koristit .next() metodu jer je stream tipa UpdatesStream koji implementira
        // Stream trait. .next() metoda je ekstenzija Stream traita definirana u StreamExt pa je zato
        // mozemo koristit na Stream traitu iako je Stream trait sam po sebi ne implementira.

        //ovo treba sve u loop{} stavit pa onda mogu subotom i nedjeljom startat i stopat pollove
        while let Some(update) = stream.next().await {
                let update = update.unwrap();
                let current_time = chrono::offset::Local::now();
                let curr_week = current_time.iso_week();
                println!("got an update");

                if let UpdateKind::Message(message) = update.kind {
                        println!("tusam");
                        // .. znači da ignoriramo sva ostala polja strukture
                        // ref znači da nam ne movea vrijednost iz message u data nego samo da posudi tj. referencira
                        if let MessageKind::Text { ref data, .. } = message.kind {
                                println!("{}: {}", &message.from.first_name, data);
                                        /*
                                        - .send() zahtjeva nešto s traitom Request, struktura SendMessage ima taj trait
                                        - mozemo konstruirat sami SendMessage ili mozemo uzet neku gotovu metodu koja ce to napravit
                                        - pošto želimo replyat na postojeću poruku -message- pogledamo kaj ta struktura nudi
                                        - u docsima vidimo blanket implementation CanReplySendMessage trait koji ima fju text_reply
                                        koji će nam vratit SendMessage. bingo.
                                        - ili mozemo napisat u sendu message.(stisni ctrl+space) pa vidimo kaj se sve nudi.
                                        - CanReplySendMessage trait je blanket trait i moze se koristit jer se on implementira na bilo
                                        čemu što implementira ToMessageId + ToSourceChat, a Message to implementira u refs.rs pa
                                        zapravo Message "naslijedi" CanReplySendMessage trait. to se zove blanket trait jer CanSend.. pokriva
                                        ova dva ToMessageId + ToSourceChat traitove.
                                        */

                                if YT_LINK_REGEX.is_match(data) {
                                        let mut playlist_with_set = PlaylistWithSet::new();
                                        let vvttv_playlist_name = &format!("vvttv {}_{}", curr_week.week(), curr_week.year())[..];
                                        println!("vvttv_playlist_name je: \"{}\"", vvttv_playlist_name);

                                        if !playlist_hashmap.contains_key(vvttv_playlist_name) {
                                                println!("{} ne postoji, radim novu playlistu", vvttv_playlist_name);
                                                playlist_with_set = match create_new_playlist(&hub, vvttv_playlist_name.to_string(), PrivacyStatus::Public).await {
                                                        Ok(playlist_with_set) => playlist_with_set,
                                                        Err(e) => match e {
                                                                Error::HttpError(_)
                                                                |Error::Io(_)
                                                                |Error::MissingAPIKey
                                                                |Error::MissingToken(_)
                                                                |Error::Cancelled
                                                                |Error::UploadSizeLimitExceeded(_, _)
                                                                |Error::Failure(_)
                                                                |Error::FieldClash(_)
                                                                |Error::JsonDecodeError(_, _) => { 
                                                                        println!("jedan od hrpe: {}", e);
                                                                        continue;
                                                                }
                                                                Error::BadRequest(e) => { 
                                                                        let send_msg = SendMessage::new(message.chat, format!("{}", e["error"]["message"]));
                                                                        api.send(send_msg).await;
                                                                        println!("create_new_playlist: badrequest je biooooooo");
                                                                        continue;
                                                                }
                                                        }
                                                };
                                                println!("napravio playlistu s imenom {:?}", playlist_with_set.playlist_name);
                                                playlist_hashmap.insert(playlist_with_set.playlist.get_playlist_name().to_string(), playlist_with_set.clone());
                                                //todo napravi poll u novom kanalu
                                                //zatvori stari poll i dodaj pobjednika u playlistu šampiona
                                        } else {
                                                playlist_with_set = playlist_hashmap.get(&vvttv_playlist_name.to_string()).unwrap().clone();
                                        }

                                        println!("vvttv_playlist_name je: \"{}\"", vvttv_playlist_name);
                                        let video_id = YT_LINK_REGEX.captures(data).unwrap().name("video_id").unwrap().as_str();
                                        println!("poruka: {}", data);
                                        
                                        //todo umjesto da hashash sve videe, mozes gledat jel repost tako da searchaš tg chat
                                        if !all_videos.contains(video_id) {
                                                let yt_link = YT_LINK_REGEX.captures(data).unwrap().name("yt_link").unwrap().as_str();
                                                let playlist_id = playlist_with_set.playlist_id.as_ref().unwrap().as_str();
                                                println!("playlist id {}", playlist_id);
                                                let video = PlaylistItem::new().set_video_parameters(video_id, playlist_id, CHANNEL_ID);

                                                let add_playlist_item = hub.playlist_items().insert(video).doit().await;
                                                match add_playlist_item {
                                                        Ok(_good) => {
                                                                println!("Added video https://www.youtube.com/watch?v={}\nto Playlist: https://www.youtube.com/playlist?list={}",
                                                                _good.1.get_video_id(), playlist_with_set.playlist.get_playlist_id());
                                                                let mut video_with_tg_data = VideoWithTgData::new();
                                                                video_with_tg_data.video_name = Some(_good.1.get_video_name().to_string());
                                                                video_with_tg_data.posted_by = Some(message.from.first_name.to_string());
                                                                video_with_tg_data.in_playlist = Some(playlist_id.to_string());
                                                                playlist_with_set.added_by.entry(message.from.first_name.clone()).and_modify(|counter| *counter += 1).or_insert(1);
                                                                // ako user ima counter 2+, onda nemoj dodat video
                                                                playlist_with_set.video_set.insert(video_id.to_string(), video_with_tg_data);
                                                                playlist_hashmap.insert(vvttv_playlist_name.to_string(), playlist_with_set);
                                                                all_videos.insert(video_id.to_string());
                                                                let send_error = api.send(&message.text_reply(
                                                                        format!("Added video https://www.youtube.com/watch?v={}\n to Playlist: https://www.youtube.com/playlist?list={}",
                                                                        _good.1.get_video_id(), data)))
                                                                        .await;
                                                                match send_error {
                                                                        Ok(_good) => (),
                                                                        Err(e) => println!("error: {:?}", e)
                                                                }
                                                        },
                                                        Err(e) => match e {
                                                                Error::HttpError(_)
                                                                |Error::Io(_)
                                                                |Error::MissingAPIKey
                                                                |Error::MissingToken(_)
                                                                |Error::Cancelled
                                                                |Error::UploadSizeLimitExceeded(_, _)
                                                                |Error::Failure(_)
                                                                |Error::FieldClash(_)
                                                                |Error::JsonDecodeError(_, _) => { 
                                                                        println!("jedan od hrpe: {}", e);
                                                                        continue;
                                                                }
                                                                Error::BadRequest(e) => { 
                                                                        let send_msg = SendMessage::new(message.chat, format!("Error: {}\nfor video\n{}", e["error"]["message"], yt_link));
                                                                        api.send(send_msg).await;
                                                                        println!("add_playlist_item: badrequest je biooooooo");
                                                                        continue;
                                                                }
                                                        }
                                                }
                                        } else {
                                                println!("Video {} already exists", video_id);
                                                let send_error = api.send(&message.text_reply(
                                                        format!("video https://www.youtube.com/watch?v={} already exists",
                                                        video_id)))
                                                        .await;
                                                match send_error {
                                                        Ok(_good) => (),
                                                        Err(e) => println!("error: {:?}", e)
                                                }
                                        }
                                }

                                // dodaj error handling ako netko nema user namješten
                                // dodaj error handling ako je netko blockao bota description: "Forbidden: bot was blocked by the user"

                                //let send_error = api.send(&message.text_reply(
                                //format!("{} has sent: {}",
                                //&message.from.first_name,
                                //data)))
                                //.await
                                //;
                        }
                }
        }

    Ok(())
}

pub async fn create_new_playlist(hub: &YouTube<HttpsConnector<HttpConnector<GaiResolver>>>, playlist_name: String, privacy_status: PrivacyStatus) -> Result<PlaylistWithSet> {
        let mut new_playlist_with_set = PlaylistWithSet::new();
        let new_playlist = Playlist::new().set_playlist_parameters(&playlist_name, privacy_status);
        let created_playlist = hub.playlists().insert(new_playlist).doit().await?;
        
        new_playlist_with_set.playlist = created_playlist.1;
        let playlist_id = new_playlist_with_set.playlist.get_playlist_id();
        new_playlist_with_set.playlist_id = Some(playlist_id.to_string());
        new_playlist_with_set.playlist_name = Some(playlist_name);
        println!("New playlist:\nhttps://www.youtube.com/playlist?list={}\nplaylist name: {}", &new_playlist_with_set.playlist_id.as_ref().unwrap(), &new_playlist_with_set.playlist_name.as_ref().unwrap());
        Ok(new_playlist_with_set)
}

pub async fn list_playlists(hub: &YouTube<HttpsConnector<HttpConnector<GaiResolver>>>, max_results: u32, channel_id: &str) -> Result<Vec<Playlist>> {
        let playlist_part: Vec<String> = vec!["snippet".to_string(), "contentDetails".to_string()];
        let playlists_response = hub.playlists()
                .list(&playlist_part)
                .max_results(max_results)
                .channel_id(channel_id)
                .doit().await?;
        Ok(playlists_response.1.items.unwrap())
}


// dodaj da ove funkcije vraćaju Result<T,E>
// ako koristimo ? umjesto match => Ok, Err
// ? će pozvat u pozadini .from metodu iz traita From da pretvori dobiveni error u error koji smo stavili kao output funkcije
// pa onda moramo implementirat .from za tu neku metodu nad kojom cemo pozvat ?
// ? odnosno .from(), mozemo iskoristit da telegram errore pretvorimo u youtube errore ili obrnuto, prilikom vraćanja errora u main, ili iz maina van programa
// pogle kak je implementiran .from() za result ili Option
//umjesto puno matchanja OK i Err, mozemo koristit unwrep_or_else()

pub async fn fetch_playlists_from_yt(hub: &YouTube<HttpsConnector<HttpConnector<GaiResolver>>>,
        playlist_hashmap: &mut HashMap<String, PlaylistWithSet>,
        all_videos: &mut HashSet<String>,
        max_results: u32, channel_id: &str) -> Result<()> {

                let playlist_part: Vec<String> = vec!["snippet".to_string(), "contentDetails".to_string()];
                let playlists_response = hub.playlists()
                        .list(&playlist_part)
                        .max_results(max_results)
                        .channel_id(channel_id)
                        .doit().await?;
                let list_of_playlists = playlists_response.1.items.unwrap();
                let playlist_item_part = vec!["snippet".to_string(), "id".to_string()];

                //list_of_playlists moze bez borrowa jer imamo ionako .to_owned,
                //pa onda ostale stavi da koriste playlist_with_set.playlist umjesto playlist, nakon mobeanja
                for playlist in &list_of_playlists {
                        let mut playlist_with_set = PlaylistWithSet::new();
                        playlist_with_set.playlist = playlist.to_owned();
                        playlist_with_set.playlist_id = Some(playlist.get_playlist_id().to_string());
                        playlist_with_set.playlist_name = Some(playlist.get_playlist_name().to_string());
                        let playlist_item_list_response = hub.playlist_items()
                                .list(&playlist_item_part)
                                .playlist_id(playlist.get_playlist_id())
                                .max_results(200)
                                .doit().await?;

                        for playlist_item in &playlist_item_list_response.1.items.unwrap() {
                                all_videos.insert(playlist_item.get_video_id().to_string());
                        }

                        println!("name: {}\t\t\tid: {}", playlist.get_playlist_name(), playlist.get_playlist_id());
                        playlist_hashmap.insert(playlist.get_playlist_name().to_string(), playlist_with_set);
                }
        Ok(())
}