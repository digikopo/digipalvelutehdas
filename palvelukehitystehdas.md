![alt](https://raw.githubusercontent.com/digiokm/palvelukehitys/master/images/digifactory.png)

## Palvelukehitystehdas - 3/30 malli
OKM KOPO vetoiset kehitysprojektit vakioidaan mahdollisimman pitkälle. Näin saamme aikaiseksi merkittäviä säästöjä, koska prosessi on selkeä ja tehokas. Kehityksessä sovelletaan "3/30 -sääntöä". Kustannus pitää olla alle 30 000 € ja kesto alle 3 kuukautta. 

Tarkoitus on saada nopealla syklillä tieto, onko ideasta tai palvelusta hyötyä, ratkooko se asiakaskunnan ongelman. Toisin sanoen nopeasti saada tieto mitä ideoita jatketaan ja mitä ei. Malli toimii myös riskienhallintana, koska näin estetään monumentaalisten projektin syntyminen, joissa yleensä kehityskaari aloituksen jälkeen on vuosia ja budjetit miljoonia. Toki varmaankin on tilanteita ja tarpeita, jolloin 3/30 mallia ei voi käyttää, mutta ne ovat harvasssa. 

### Toteutus 3 kuukauden versiosprinteissä

Säännön mukaan jokaisen uuden projektin **toteutusvaihe saa kestää enintään 3 kuukautta**, jonka jälkeen pitää olla esittää konkreettisia tuloksia. Tuloksen ei odoteta olevan valmis palvelu tai ratkaisu vaan enemmänkin proof of concept tyyppinen toteutus. Selkeyden vuoksi mainittakoon että määrittelyn kirjoittaminen projektina ei kelpaa. Tuloksien tulee olla käytännöllisiä ja lopputuoteen tai palvelun saavuttamista edistävä konkreettinen totetus. 

### Alle 30 000€

Vaiheen **kustannukset saa olla maksimissaan 30 000€**. Alle 30 000€ hankinnat voidaan tehdä huomattavasti kevyemmällä prosessilla ja nopeammin. Lopuksi projektin tuotokset arvioidaan ja päätetään jatkosta: ei jatku tai jatkuu uudella sunnitelmalla eli uusi kierros (alla olevassa kuvassa alempi osa "Jatkoprojekti"). 

Jokainen projekti lähtee ideasta, joita kerätään tilannehuoneen seinälle. Idean saa koska tahansa muuttaa [canvas pohjalle](https://github.com/digiokm/palvelukehitys/blob/master/tilannekuvahuone.md#2-suunnittelu) tehdyksi "businessplaniksi", jossa on olennaiset asiat tiiviisti. Canvaksen idea on otettu lean startup toimintatavoista, jossa jäte eli turhat kehityskulut pyritään minimoimaan ja oppimistulokset maksimoimaan. Tilannekuvan tarkastelupalaverissa käydään uudet canvas tasolle kehittyneet ideat läpi ja mietitään niiden tarpeellisuutta. Kun idea saa kannatusta ja se sopii muuhun kehitystoimintaan, löytyy resursseja ja aikaa, täydennetään canvas toteutussuunnitelmaksi, jonka kuvassa annettu maksimi laatimisaika on ohjeellinen. Toteutussuunnitelman hyväksytään tai hylätään tilannekuvan tarkastelupalaverissa (luettu etukäteen). Toteutussuunnitelman laatii yleensä idean esittäjä. Osana toteutussuunitelmaa tulee selvittää: 
* onko idealla myös ylemmän johdon hyväksyntä
* onko resursseja ja paljonko
* mitkä tulee olemaan kulut
* ketkä ovat asiakasedustajina mukana
* kehitysyhteisön jäsenet (ml yritykset, mielellään nälkäisiä ja ketteriä)

Kun projekti on hyväksytty tulee tehdä heti oma repository Github -palveluun DigiOKM alle ja siirtää toteutussuunnitelman githubiin esim markdown merkkausta hyväksikäyttäen. Markdown pohjainen dokumentti voi pidemmän päälle on fiksumpi lähestymistapa, koska jatkovaiheiden (voi olla useita) kohdalla suunnitelmaa täydennetään. Suunnitelman ylläpidosta vastaa yksi henkilö, joten ei ole tarvetta yhtäaikaiselle editoinnille ja siksi Github sopii tähän. Muussa tapauksessa tulisi käyttää muuta kuten esim Hackpad alustaa. 

![alt](https://raw.githubusercontent.com/digiokm/palvelukehitys/master/images/projekti-tehdas-kaavio.png)

**Jatkoprojekti budjetti voi olla suurempi kuin 30 000€**. Mikäli määrä ylittää 100 000€, viedään projekti hankesalkkuun. Kun projekti tulee toisen kierroksen päähän, tehdään jälleen evaluointi. Tällä kertaa päätetään että 
* onko vielä kehitettävää tai 
* riittääkö resurssit jatkaa nyt. 

Jos ei, siirtyy palvelu ylläpitoon. Muussa tapauksessa palataan canvaksen päivitykseen ja toteutussuunnitelman päivitykseen. Kuvassa oleva 2 viikon päivitysaika on ohjeellinen ja sitä on muuutettava tarpeen mukaan. 

### Ylläpito
Palveluiden ylläpidon suhteen ei paljon ole vaihtoehtoja. Jos jää itselle ylläpitoon niin joko OPH:n palvelimet tai sitten CSC:lle. Kummatkaan eivät ole ilmaisia. Jos taas ulkoistetaan tai ostetaan palveluna, niin sitten ylläpito tulee palveluntarjoajalta. Projektipäällikön tehtävä on varmistaa, että ylläpito on ratkaistu. Tulisi harkita vakavasti toimialan yhteistä open stack tyyppistä alustaa, jonne palvelut voisi siirtää ylläpitoon. Tällöin tulee huomioida että pelkkä palvelinympäristö ei riitä. Tarvitaan henkilöstöä joka pitää palvelusta huolta ja korjaa kiireisimmät bugit ja tietoturvaongelmat.  
