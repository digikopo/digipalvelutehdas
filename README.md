# OKM toimialan API- ja palvelukehitysmalli

OKM toimialana tarvitsee jalkautuksen sisältävän API strategian osana arkkitehtuurisuunnittelua. Strategioita on jo monia kuten esimerkiksi älystrategia, mutta niiden vika on että ne jäävät paperitiikereiksi…tai oikeastaan bittitiikereiksi makaamaan palvelimien ja kovalevyjen nurkkiin. Lähtökohta tulee olla palvelujen rakentaminen osaksi kansallista palveluarkkitehtuuria. Kaikkien toimien tulee edistää tätä tavoitetta ja madaltaa kynnystä innovoida uusia tapoja käyttää digitalisoituvaa tietoa entistä tehokkaammin ja monipuolisemmin.

Teollinen internet, josta paljon puhutaan on nimenä harhaanjohtava. Kyse on teollisesta vallankumouksesta jonka vaikutukset ulottuvat koko yhteiskuntaan ja samat periaatteet tulevat vaikuttamaan jokapäiväiseen elämäämme. Teollinen internet (joskus myös esineiden internet < engl. The Internet of Things tai IoT) viittaa yksilöitävissä olevien sulautettujen tietokoneiden kaltaisten järjestelmien yhteenliitokseen olemassaolevan internetin infrastruktuurissa. Teollisuuden murroksessa perinteisissä teollisuustuotteissa aletaan hyödyntää internetiä, nanotekniikkaa sekä muuta viestintä- ja tietotekniikkaa. Teollisessa internetissä esineille annetaan tunnistettava identiteetti ja ne alkavat viestiä keskenään. Verkkoon kytkeytyvät laitteet voivat olla esimerkiksi teollisuus-, koti-, palvelu- tai hoivarobotteja. Emme siis opetussektorina voi tuudittautua uneen ja olla ottamatta ympärillä tapahtuvaa muutosta huomioon. Teollisen internetin yksi keskeisin elementti on webpohjaiset rajapinnat (API, Application Programmin Interface).

Toimialan julkisin varoin tuotetusta tiedosta on tehtävä avointa. Tieto on jaettava ilmaiseksi ja erityistä huomiota on kiinnitettävä julkisen tiedon rajapintoihin (API). Tieto, joka ei ole yksinkertaisesti ja automaattisesti haettavissa ja hyödynnettävissä, ei ole kovin arvokasta digitalisaation edistämisessä. 

[JHS-järjestelmän mukaiset suositukset](http://www.jhs-suositukset.fi) koskevat valtion- ja kunnallishallinnon tietohallintoa. Sisällöltään JHS voi olla julkishallinnossa käytettäväksi tarkoitettu yhtenäinen menettelytapa, määrittely tai ohje. JHS-järjestelmän tavoitteena on parantaa tietojärjestelmien ja niiden tietojen yhteentoimivuutta, luoda edellytykset hallinto- ja sektorirajoista riippumattomalle toimintojen kehittämiselle sekä tehostaa olemassa olevan tiedon hyödyntämistä. Suosituksilla pyritään myös minimoimaan päällekkäistä kehittämistyötä, ohjaamaan tietojärjestelmien kehittämistä ja saamaan aikaan hyviä ja yhdenmukaisia käytäntöjä julkishallintoon ja erityisesti julkisten organisaatioiden tietohallintoon. Suositukset hyväksyy julkisen hallinnon tietohallinnon neuvottelukunta JUHTA ja niiden laatimista ohjaa JUHTAn alainen JHS-jaosto. OKM:n tulee aktiivisesti osallistua JHS työhön, hyödyntää olemassa olevaa ja viedä omia hyviä käytäntöjään osaksi JHS-järjestelmää.  

Perusperiaatteet toiminnalle löytyy [Tim O’Reillyn digitaalisen hallinnon pääkohdista](http://chimera.labs.oreilly.com/books/1234000000774/ch02.html#lesson_1_open_standards_spark_innovation): 
* Tue avoimia standardeja.
* Suunnittele palvelut tukemaan aktiivista osallistumista.
* Tee asioiden kokeilemisesta helppoa.
* Opi ulkopuolisilta osaajilta.
* Luo edistymisen mittaamisen kulttuuri.
* Rakenna yksinkertaisia digitaalisia palveluita, joita on helppo kehittää

Lista sisältää strategisia linjauksia ja ohjausta. Alla on avattu perusperiaatteita tarkemmin ja esitelty tarvittavat toimenpiteet ja suositukset. 

## Rajapintojen kehittäminen avoimella lähdekoodilla

Avoimet rajapinnat ovat hyvä mutta riittämätön lähtökohta API strategialle. Rajapinnat tulee tehdä avointa lähdekoodia käyttäen. Pelkkien avoimien rajapintojen edistäminen ei riitä. Vaikka rajapinnat ovat avoimia ja kaikkien käytössä, myös rajapinnat muuttuvat käyttäjien tarpeiden mukaisesti. Rajapinnan kehittäminen puolestaan vaatii tuntemusta taustajärjestelmästä ja suljetun komponentin kohdalla se tieto on vain tuotteen omistajalla. Tämä puolestaan johtaa siihen tilanteeseen, että suljetun tuotteen omistaja voi mielivaltaisesti päättää mitä muutoksia rajapintaan tehdään jos tehdään ollenkaan. Toiseksi, tämä tilanne estää muutosten kehittämisen vapaan kilpailuttamisen kyseisen komponentin toteuttamien ominaisuuksien osalta. Näin ollen päädytään lähelle perinteistä vendor lock-in tilannetta. Kun kukaan ei tiedä mitä muutosten tekeminen vaatii, voi tuotteen omistaja mielivaltaisesti määritellä kulut tai todeta ettei haluttuja muutoksia voi tehdä.

Lisäksi julkinen sektori on velvoitettu tuottamaan avointa tietoa ja edistämään keinoja uudelleenkäyttää tietoa. Näin ollen tulee huomioida rajapintoja ja palveluita kehitettäessä avoimen tiedon tarpeet. Toimialan julkisten toimijoiden tulee edistää avoimen tiedon määrän lisäämistä ja tiedon laadun parannusta. 

**Toimenpiteet ja suositukset**
* Sovelletaan [JHS 189](http://docs.jhs-suositukset.fi/jhs-suositukset/JHS189/JHS189.html):a rajapintatoteuksien tilaamisessa ja tuotannossa. 
* Avoimen tiedon laajamittainen soveltaminen palveluissa [JHS 169](http://docs.jhs-suositukset.fi/jhs-suositukset/JHS169/JHS169.html)

## Yhdenmukaisesti käyttäytyvät rajapinnat

Rajapintojen tulee olla tarkoitukseen sopivia. Monesti kevyet teknologiat kuten JSON ja REST ovat hyvä lähtökohta ja niitä tuleekin harkita ensimmäisenä vaihtoehtona. Vasta perustellusti voi käyttää muita teknologioita kuten XML ja SOAP. Rajapintojen tulee rakentua ja käyttäytyä loogisesti samalla lailla. Tämä edistää ja nopeuttaa rajapintojen käyttöönottoa palveluita kehitettäessä. Esimerkiksi Kun kehittäjä oppii että opetussektorin rajapintojen virhetilanteidenkäsittely menee tyypillisesti yhdellä ja samalla tavalla, ei kehittäjän tarvitse opetella tai implementoida omassa ratkaisussaan koodia uudelleen vaan hän voi uudelleenkäyttää aiemmin opittua ja tuotettua. 


**Toimenpiteet ja suositukset**
* Määrittää ja ottaa käyttöön [API parhaat käytännöt](https://github.com/digiokm/api-standards)

## Keskitetty kehitysympäristö ja versionhallinta

Kehityksessä tulee käyttää aina kun mahdollista JulkICTLab ympäristöä. Lisäksi OKM:n toimialana tulee keskittää lähdekoodinhallinta Github palveluun tai vaihtoehtoisesti käyttää palveluavastaavaa ratkaisua Gitlab, joka löytyy jo valmiiksi JulkICTLabista. Github palvelun käyttöä puoltaa se fakta, että kehittäjät ovat jo siellä. Github palveluna on avoimen lähdekoodin yhteisön de facto palvelu ja siten kehittäjäpohja laaja. Eriytymällä omaan Gitlab palveluun eristämme itsemme muusta kehittämisyhteisöstä. On kuitenkin tilanteita, jolloin Gitlab käyttö opn perusteltua. Oletusarvoisesti kuitenkin käytetään Github palvelua. 

**Toimenpiteet**
* Ministeriö ottaa Githubin käyttöön ja keskittää kehitysprojektiensa versionhallinnan Github palveluun oman organisaation alle. 
* Github organisaatiolle nimetään vastaava henkilö
* Github ympäristöä ja sen sisältämää tietoa hyödyntävän reaaliaikatilannekuvanäkymän luominen organisaatioittain (OKM, Opetushallitus, YTL). Eräänlainen dashboard joka mahdollistaa tiedon esittämisen kuvaajina. 
* ...

## Asiakas ja asiakas

Toinen ohjaava arvo on design lähtöisyys. Palveludesign on jo jonkin aikaa ollut selkeästi nousussa osittain siitä syystä että se nostaa asiakkaan keskiöön. Kokeilukulttuuri ja asiakkaiden osallistaminen kehittämiseen ovat tärkeä osa digitalisaatiota.

Hyviä ja käytettyjä palveluita ei luoda ilman asiakkaan kuulemista. Asiakas tulee ottaa design prosessiin mukaan niin aikaisin kuin mahdollista. Sama pätee rajapintoihin. Rajapintojen asiakas vain on eri kuin palvelujen asiakas. Palvelujen asiakas on Matti tai Maija Meikäläinen, joka palveluväylän kautta selaimella hoitaa arkensa asioita sinne luotujen palvelujen avulla. Rajapinnan asiakas on kehittäjä, se taho joka puolestaan rakentaa Matille ja Maijalle palvelujen käyttöliittymät ja logiikat palveluväylään.

**Toimenpiteet**
* ....

## Keskitetty rajapintojen hallinta
 
Toimialalla on jo useita REST pohjaisia rajapintoja muun muassa opintopolku järjestelmässä. Lisää palveluita ollaan kehittämässä, kuten esimerkiksi todennetun osaamisen rekisteri (TOR). Rajapintoja tulee väistämättä lisää ja suunta onkin laajasti rajapintoja hyödyntäviä palveluita kohti (kts kuva alla). Digitaaliset palvelut tyypillisesti käyttävät useaa rajapintaa kerätäksen tarvittavat tiedot, jotta voivat palvella asiakasta tarkoituksenmukaisesti pompottamatta digitaaliselta "luukulta" toiselle esittäen tiedot yhdessä näkymässä.

Palveluväylässä on rajapintojen hallinta, mutta kaikki rajapinnat OKM toimialalla eivät käytä palveluväylää. Eikä ole tarkoituksenmukaista edes pakottaa kaikkia käyttämään palveluväylää. Ainakaan avoimen tiedon rajapinnat tulee eriyttää palveluväylästä ainakin aluksi. 

Näin ollen tulee perustaa keskitetty rajapintojen hallintapalvelu ainakin avoimille rajapinnoille. Keskitetty rajapintojen hallinta liittyy tuotteenhallintaan, jonka malli puolestaan on määritelty VTT:n kehittämässä avoimen tuotteen hallintamallissa.

![alt text](https://raw.githubusercontent.com/digiokm/palvelukehitys/master/images/keskitetty-api-hallinta.png)

Hallintaratkaisu tulisi olla koko toimialan yhteinen ja näin keskittämällä saataisiin säästöjä. Mikäli erilaiset toimijat keskittävät rajapintojen hallinnan yhteen (kahdennettuun ja varmistettuun) API:en hallintapalveluun, nousee rajapintojen hyödynnettävyys huomattavasti. Silloin palvelujen kehittäjät löytävät tarvitsemansa tiedot ja kehittäjäyhteisön yhdestä paikasta. 

**Toimenpiteet ja suositukset**
* Perustaa koko toimialan käyttöön yhteinen API:en hallintaratkaisu (ei vain julkiselle sektorille, kaupallisille tahoille maksullinen) 
* Sovittaa API:en hallinta osaksi avoimen tuotteen hallintamallia osana API hallintamallin kehittämistä. 

## Avoimen tuotteen hallintamalli

VTT-Technical-Research-Centre-of-FinlandKehittämisen konseptina tulee hyödyntää Avoimen tuotteen hallintamallin mukaista tuotteenhallintasuunnitelmaa. Avoimen tuotteen hallintamalli määrittelee säännöt, joilla voidaan perustaa julkisen hallinnon organisaatioille käyttäjäyhteisö avoimen lähdekoodin ohjelmistotuotteen kehittämistä, ohjausta ja hallintaa varten. Malli selkeyttää mm. tuotteen omistajuutta, osapuolten vastuita sekä palvelun ylläpidon ja kehittämisen ohjausta. VTT:n luomaa mallia pyritään soveltamaan kaikissa JulkICT:n projekteissa, joissa tuotetaan palveluja avoimella lähdekoodilla. Kuten aiemmin on todettu asiakkuuksia on ainakin kahden tyyppisiä, joista rajapinnan asiakas on kehittäjä. Rajapinta tulee siis nähdä palveluna siinä missä Matti ja Maija Meikäläisen käyttämät palveluväylän näkymät. Rajapinta on tuote ja sen kehittämiseen tulee käyttää myös Avoimen tuotteen hallintamallin mukaista tuotteenhallintasuunnitelmaa.

Avoimen tuotteen hallintamallia tulee kehittää edelleen yhteistyössä VTT:n ja muiden tahojen kanssa. Mallia tulee kehittää siten, että se ottaa huomioon rajapintojen kehittämisen erityispiirteet. Alla oleva malli on yksi tapa nähdä rajapintojen kehittämisen malli.
![alt text](https://raw.githubusercontent.com/digiokm/palvelukehitys/master/images/apiops.png)

**Toimenpiteet**
* ....

## Iteratiivista ketterää kehitystä

**Avainsanat**
* osallistava
* avoin
* ketterä
* kokeilukulttuuri

Massiiviset yli vuoden mittaiset rajapintojen kehitysprojektit tulee kieltää. Sen sijaan tulee kehittää kokeilukulttuuria ja tarvittaessa sisällyttää Avoimen tuotteen hallintamalliin. Digitalisaatiosta saadaan paras hyöty, kun yhteiskunnan kaikki prosessit suunnitellaan kokonaan uudella digitaalisuuteen sopivalla tavalla. Lisäksi tarvitaan kokeiluja eikä loppuun saakka hiottuja täydellisiä suunnitelmia. Toteutus tulee olla MVP tyyppiseen minimaalisen toteutukseen perustuvaa, jolloin tehdään vain välttämättömin osuus. Syntynyt tuotos testataan välittömästi loppukäyttäjillä ja saadun palautteen mukaan jatketaan kehitystä. Toisin sanoen kehitys tulee tapahtua avoimesti alussa raakileita ja keskeneräistä (mutta toimivaa) tuotosta hyväksikäyttäen.

**Toimenpiteet**
* ....


## Palvelukehityksen portaali

Keskitetty rajapintojen hallintapalvelusta on osa laajempaa kokonaisuutta, josta löytyy myös ajantasaiset rajapintojen dokumentaatiot, valmiit koodiesimerkit rajapintojen hyödyntämiseen, valmiit ohjelmistokomponenttikirjastot eri käyttöjärjestelmille (SDK), hiekkalaatikko API:en kokeilemiseen ja mahdollisuus vuorovaikutukseen kehittäjäyhteisön kanssa. Tässä kohdin tulee hyödyntää FORGE alustaa ja yhteisöä.

Portaali tarjoaa rajapintojen asiakkaille eli palvelukehittäjille yhden pisteen, josta tieto ja rajapinnat löytyvät. Tämä puolestaan selkeyttää ja nopeuttaa palvelukehitystä, joka kuten aiemmin on todettu tulee entistä enemmän pohjautumaan webpohjaisten rajapintojen hyödyntämiseen.

**Toimenpiteet**
* ....
