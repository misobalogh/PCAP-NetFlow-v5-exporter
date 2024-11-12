# Titulna strana

# Obsah

# Uvedenie do problematiky

## Zadanie
Za ulohu som mal vytvorit program p2pnprobe, ktory bude extrahovat informacie o tokoch z PCAP suboru. Tieto toky bude odosielat na kolektor vo formate NetFlow v5. 

Program prijma rozne argumenty, pomocou ktorych sa da nastavit, ako budu toky agregovane a kam ich bude odosielat (viz #Navod na pouzitie). 

Program bude na vstupe citat pakety z PCAP suboru zadaneho ako argument programu a tie spracuje a agreguje do tokov. Toky potom pomocou protokolu UDP odosle na NetFlow v5 kolektor, kde su tieto toky dalej spracovane a analyzovane. Program p2nprobe je len exporter a je zamerany len na zaznamy o tokoch TCP.

## Zakladne informacie
NetFlow v5 protokol vyvinuty spolocnostou Cisco a sluzi na monitorovanie a analyzu sietoveho toku dat. Sluzi na zbieranie informacii o sietovej prevadzke a naslednu analyzu na ucely monitorovania, optimalizacie a bezpecnosti siete.

Toky su agregovane podla urcitych kriterii, ako su napriklad IP adresa odosielatela a prijimatela, porty, protokol a dalsie. Podla nich su prichadzajuce pakety jedinecne identifikovatelne a priradene do tokov. 

Tok moze byt ukonceny roznymi spospobmi. V program p2nprobe je tok ukonceny troma sposobmi: 
    - po uplynuti aktivneho timeoutu
    - po uplynuti neaktivny timeoutu

Aktivny timeout je casovy interval, po ktorom je tok ukonceny, aj ked do neho stale prichadzaju pakety.

Neaktivny timeout je casovy interval, po ktorom je tok ukonceny, ak do neho neprichadzaju ziadne pakety po nejaky cas.

Exporter ukocnene toky uchovava v pamati a po nazbierani maximalneho poctu tokov v pamati alebo precitani posledneho paketu zo suboru, ich odosle na kolektor. Odoslany UDP datagram obsahuje hlavicku a zaznamy, ktorych podla specifikacie od spolocnosti Cisco je v rozsahu 1-30.


# Navrh aplikacie
Program je rozdeleny do viacerych logickych casti, ktore vykonavaju urcite ulohy:
- Nacitanie argumentov programu a ich spracovanie - ArgParser
- Nacitanie paketov zo suboru o extrahovanie podstatnych informacii - PcapReader
- Sprava a agregacia tokov - FlowManager
- Odosielanie tokov na kolektor - Exporter

Program najprv spracuje vstupne argumenty a skontroluje ich validitu pomocou modulu ArgParser. Nasledne modul PcapReader nacita pakety zo suboru zadaneho pomocou agrumentu. Kazdy paket je spracovany a su z neho extrahovane informacie, ktore su potrebne na identifikaciu toku a informacie potrebne pre statistiky. Tieto informacie su poslane do modulu FlowManager, ktory z nich vytvori jedinecny kluc pomocou ktoreho identifikuje tok ak nejaky tok s tymto klucom existuje, alebo vytvori novy. Ak FlowManager vyhodnoti tok ako expirovany pomocou informacii z paketu alebo informacii od modulu PcapReader, ze precital posledny paket z PCAP suboru, je odoslany na kolektor pomocou modulu Exporter. 


# Popis implementacie
Nizsie je zobrazeny class diagram, ktory zobrazuje ako su jednotlive moduly programu p2nprobe implementovane a ako spolu komunikuju. 

## Diagram
![Class diagram](docs/class_diagram.svg)

## Implemetacia
Program p2nprobe je implementovany v jazyku C++ verzia C++17 a vyuziva kniznicu libpcap na citanie a spracovanie paketov. 

### Pouzite kniznice:

- **libpcap**
   - čítanie PCAP súborov a extrahovanie informácií z paketov

- **arpa/inet.h**
   - konverzia IP adries a portov medzi sieťovým a hostiteľským formátom

- **netinet/ip.h, netinet/tcp.h**
   - parsovanie sieťových hlavičiek

- **sys/socket.h**
   - odosielanie NetFlow záznamov na kolektor

- **unordered_map, vector, string**
   - ukladanie a správu tokov a záznamov

- **ctime, chrono**
   - práca s časovými značkami a meranie času

- **iostream, sstream**
   - formátovanie výstupu (sprava help, rozne chybove hlasky)

- **memory**
   - Smart pointre a správa pamäte

### Konkretne moduly 

#### ArgParser
Modul na nacitanie vstupnych argumentov programu, spracovanie a overenie, ci su argumenty validne. V pripade chyby alebo chybajucich povinnych argumentov vypise chybovu hlasku a ukazku, ako spustit program. Argument -h vypise "help" spravu, ktora informuje uzivatela o pouziti programu a jednotlivych argumentoch.

#### ErrorCodes
Definicie roznych chybovych hlasok, pre lepsie rozpoznavanie, aka chyba nastala.
Mozne chybove kody:
- 0 - Bez chyby
- 1 - Vnutorna chyba, napriklad chyba alokacie pamati
- 2 - Nespravne argumenty
- 3 - Chyba pri otvarani suboru
- 4 - Chyba pri citani paketu
- 5 - Paket obsahuje nevalidne informacie

Implementuje aj funkciu ExitWith pre konzistentné ukončenie programu, na zjednodušenie správy chybových stavov.

#### PcapReader
Trieda na čítanie paketov zo súboru a ich spracovanie. Poskytuje rozhranie pre extrakciu TCP paketov a základných informácií z paketov a tie ulozi do struktury NetFlowV5record.

#### FlowManager
Hlavná trieda zodpovedná za správu a agregáciu tokov. Vytvara toky a kluce pre ne podla informacii z paketu. Pomcou tychto klucov potom vie identifikovat, ci tok uz existuje alebo nie. Ak tok existuje, prida paket do toku. Ak tok neexistuje, vytvori novy tok a prida paket do neho. Na efektivne vyhladavanie využíva kombinovanú dátovú štruktúru (hash mapa + linked list) pre efektívne vyhľadávanie a správu tokov. Hash mapa sluzi na rychle vyhladanie tokov pomocou kluca a linked list obsahuje odkazy do hashmapy, ale zaroven udrzuje poradie, v akom sa toky vytvorili. 

#### NetFlowV5Key
Implementácia unikátneho kľúča pre identifikáciu tokov. Kombinuje 5 kľúčových polí (zdrojová/cieľová IP, porty a protokol) pre jednoznačnú identifikáciu toku. Využíva preťaženie operátora `==` pre porovnávanie kľúčov a implementuje vytvorenie kluca z udajov, ktore su mu dane pre použitie v hash mape.

#### Exporter
Modul pre formátovanie a export NetFlow záznamov na kolektor. 
Modul formatuje NetFlow záznamy (struktura NetFlowV5record) a NetFlow hlavicky (strukuta NetFlowV5header) podľa špecifikácie NetFlow v5 a odosiela ich na kolektor specifikovany v programovych argumentoch pomocou protokolu UDP. Rata pocet odoslanych paketov, kedze tento udaj je potrebny v hlavicke NetFlow zaznamu.

#### Flow
Reprezentácia jednotlivého sieťového toku, ktorá zapuzdruje všetky potrebné informácie o toku a jeho štatistiky.



# Zakladne informacie o programe

# Navod na pouzitie

# Popis testovania aplikacie

# Vysledky testov

# Bibliografia