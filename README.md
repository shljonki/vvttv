Rust Telegram Bot Library
=========================

Telegram bot for adding youtube videos to specific playlists. Each week new playlist is created. Users can add videos to playlist by sending them inside telegram group which has this bot added. At the end of the week poll is started automatically with options that match sent video names. Users vote for best video of previous week and winning video is added to a new "winner" playlist. Bot does not allow reposts and can set how many entries can be applied by person by week.
This bot is based on existing crates that use Telegram APIs and Youtube APIs.

<table>
  <tbody>
    <tr>
      <td><b>Documentation:</b></td>
      <td><a href="https://docs.rs/telegram-bot/">Latest crates.io version</a></td>
      <td><a href="https://telegram-rs.github.io/telegram-bot/telegram_bot/"><code>master</code></a></td>
    </tr>
  </tbody>
</table>

A library for writing your own [Telegram](https://telegram.org/) bots. More information [here](https://core.telegram.org/bots). Official API [here](https://core.telegram.org/bots/api).

## Example
Here is a simple example (see [`example/simple.rs`](https://github.com/telegram-rs/telegram-bot/blob/master/lib/examples/simple.rs)):

``` rust
use std::env;

use futures::StreamExt;
use telegram_bot::*;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let token = env::var("TELEGRAM_BOT_TOKEN").expect("TELEGRAM_BOT_TOKEN not set");
    let api = Api::new(token);

    // Fetch new updates via long poll method
    let mut stream = api.stream();
    while let Some(update) = stream.next().await {
        // If the received update contains a new message...
        let update = update?;
        if let UpdateKind::Message(message) = update.kind {
            if let MessageKind::Text { ref data, .. } = message.kind {
                // Print received text message to stdout.
                println!("<{}>: {}", &message.from.first_name, data);

                // Answer message with "Hi".
                api.send(message.text_reply(format!(
                    "Hi, {}! You just wrote '{}'",
                    &message.from.first_name, data
                )))
                .await?;
            }
        }
    }
    Ok(())
}
```
## Notes
Some files were removed for security reasons
