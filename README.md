
The Son of Lobber
=================

The lobo2 project is a simple bittorrent tracker and metadata repository with support for (and expecting the presense of) federated authentication infrastructure.

There is also an OAUTH2-authenticated API. Possible use-cases include distribution of research datasets and library services. Unline its predecessor (the lobber codebase), lobo2 doesn't include any clent-side support, instead it is assumed that users will figure out how to integrate with the lobo2 API. Also there are no presumptions on access-control for torrents/datasets: lobo2 is for public data - if you want semi-private filesharing we recomment BitTorrent Sync (btsync).
