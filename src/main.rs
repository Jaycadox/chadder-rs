use cursive::align::HAlign;
use cursive::theme::Effect::Bold;
use cursive::theme::Palette;
use cursive::theme::{BaseColor, BorderStyle};
use cursive::utils::markup::StyledString;
use cursive::view::Nameable;
use cursive::view::Resizable;
use cursive::view::ScrollStrategy;
use cursive::view::Scrollable;
use cursive::views::Dialog;
use cursive::views::DummyView;
use cursive::views::EditView;
use cursive::views::LinearLayout;
use cursive::views::ScrollView;
use cursive::views::TextView;
use cursive::Cursive;
use cursive::With;
use lazy_static::lazy_static;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use crate::client::Client;
mod client;
mod server;
mod shared;

//fn main() {
//    std::thread::spawn(move || {
//        let rt = tokio::runtime::Builder::new_current_thread()
//        .enable_all()
//        .build()
//        .unwrap();
//        rt.block_on(async {
//            println!("Server stopped with result: {:?}", server::start().await);
//        });
//
//    });
//    std::thread::spawn(|| {
//        let client = Arc::new(Mutex::new(client::Client::new("test123".to_owned())));
//        let client_1 = Arc::clone(&client);
//        client.lock().unwrap().on_message_receive(|msg| {
//            // println!("New message: {}", msg);
//        });
//        std::thread::spawn(move || {
//            let rt = tokio::runtime::Builder::new_current_thread()
//            .enable_all()
//            .build()
//            .unwrap();
//            rt.block_on(async {
//                Client::start(client_1).await.unwrap();
//            });
//
//        });
//        loop {
//            client.lock().unwrap().send_message("yo this is cool".to_owned());
//            std::thread::sleep(Duration::from_millis(200));
//        }
//
//    });
//    loop {}
//}

#[tokio::main]
async fn main() {
    let server = Rc::new(RefCell::new(false));
    let b_serv = Rc::clone(&server);
    let mut siv = cursive::crossterm();
    siv.set_theme(cursive::theme::Theme {
        shadow: true,
        borders: BorderStyle::Simple,
        palette: Palette::default().with(|palette| {
            use cursive::theme::BaseColor::*;
            use cursive::theme::Color::*;
            use cursive::theme::PaletteColor::*;

            palette[Background] = TerminalDefault;
            palette[View] = TerminalDefault;
            palette[Primary] = White.dark();
            palette[TitlePrimary] = Blue.light();
            palette[Secondary] = Black.light();
            palette[Highlight] = Black.light();
        }),
    });
    siv.add_fullscreen_layer(
        Dialog::around(
            LinearLayout::vertical()
                .child(TextView::new("Username"))
                .child(
                    EditView::default()
                        .on_submit(|s, _| {
                            let name = s.find_name::<EditView>("name").unwrap();
                            let ip = s.find_name::<EditView>("host").unwrap();
                            chat(
                                s,
                                name.get_content().to_string(),
                                ip.get_content().to_string(),
                            );
                        })
                        .with_name("name"),
                )
                .child(TextView::new("Server"))
                .child(
                    EditView::content(EditView::default(), "127.0.0.1")
                        .on_submit(|s, _| {
                            let name = s.find_name::<EditView>("name").unwrap();
                            let ip = s.find_name::<EditView>("host").unwrap();
                            chat(
                                s,
                                name.get_content().to_string(),
                                ip.get_content().to_string(),
                            );
                        })
                        .with_name("host"),
                ),
        )
        .button("Start client", |s| {
            let name = s.find_name::<EditView>("name").unwrap();
            let ip = s.find_name::<EditView>("host").unwrap();
            chat(
                s,
                name.get_content().to_string(),
                ip.get_content().to_string(),
            );
        })
        .button("Start server", move |siv| {
            let mut serv = b_serv.as_ref().borrow_mut();
            *serv = true;
            Cursive::quit(siv);
        })
        .title("Connection info")
        .full_screen(),
    );
    siv.run();
    if *server.as_ref().borrow() {
        server::start().await.unwrap();
    }
}

lazy_static! {
    static ref MESSAGE_QUEUE: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(vec!()));
    static ref SEND_MESSAGE_QUEUE: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec!()));
}

fn chat(s: &mut Cursive, name: String, ip: String) {
    let client: Arc<Mutex<Client>> = Arc::new(Mutex::new(Client::new(name, ip)));
    let thr_client = Arc::clone(&client);
    let cursive: Arc<Mutex<&mut Cursive>> = Arc::from(Mutex::from(s));
    let cb_sink = cursive.lock().unwrap().cb_sink().clone();
    let cb_sink_2 = cursive.lock().unwrap().cb_sink().clone();
    client.lock().unwrap().on_message_receive(|sender, msg| {
        MESSAGE_QUEUE.lock().unwrap().push((sender, msg));
    });

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            if let Err(err) = Client::start(client).await {
                cb_sink_2
                    .send(Box::new(move |s| {
                        s.add_layer(Dialog::text(format!("Error: {}", err)))
                    }))
                    .unwrap();
            } else {
                cb_sink_2
                    .send(Box::new(move |s| {
                        s.add_layer(Dialog::text("Connection to server lost"))
                    }))
                    .unwrap();
            }
        });
    });

    std::thread::spawn(move || loop {
        for m in SEND_MESSAGE_QUEUE.lock().unwrap().iter() {
            thr_client.lock().unwrap().send_message(m.to_owned());
        }
        SEND_MESSAGE_QUEUE.lock().unwrap().clear();
        cb_sink
            .send(Box::new(move |s| {
                let mut list = s.find_name::<LinearLayout>("message_list").unwrap();
                for m in MESSAGE_QUEUE.lock().unwrap().iter() {
                    list.add_child(
                        LinearLayout::horizontal()
                            .child(
                                TextView::new(StyledString::styled(
                                    format!("{}: ", m.0),
                                    cursive::theme::Color::Light(match m.0.as_str() {
                                        "System" | "Client" => BaseColor::Black,
                                        _ => BaseColor::Yellow,
                                    }),
                                ))
                                .style(Bold),
                            )
                            .child(
                                TextView::new(StyledString::styled(
                                    m.1.to_owned(),
                                    match m.0.as_str() {
                                        "System" => cursive::theme::Color::Light(BaseColor::Yellow),
                                        "Client" => cursive::theme::Color::Light(BaseColor::Green),
                                        _ => cursive::theme::Color::Light(BaseColor::White),
                                    },
                                ))
                                .h_align(match m.0.as_str() {
                                    "System" | "Client" => HAlign::Center,
                                    _ => HAlign::Left,
                                })
                                .full_width(),
                            ),
                    )
                }
                MESSAGE_QUEUE.lock().unwrap().clear();
            }))
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));
    });
    cursive.lock().unwrap().pop_layer();

    cursive.lock().unwrap().add_layer(
        Dialog::around(
            LinearLayout::vertical()
                .child(
                    ScrollView::new(
                        LinearLayout::vertical()
                            .with_name("message_list")
                            .full_width(),
                    )
                    .scroll_strategy(ScrollStrategy::StickToBottom)
                    .fixed_height(15),
                )
                .child(DummyView.fixed_height(1))
                .child(TextView::new("Compose message"))
                .child(
                    EditView::default()
                        .on_submit_mut(move |siv, _content| {
                            let mut compose = siv.find_name::<EditView>("compose").unwrap();
                            let content = compose.get_content().to_string();
                            SEND_MESSAGE_QUEUE.lock().unwrap().push(content);
                            compose.set_content("");
                        })
                        .with_name("compose"),
                )
                .scrollable(),
        )
        .title("Chadder client")
        .fixed_width(70)
        .fixed_height(20),
    );
}
