import secrets, string

random = secrets.SystemRandom()

words = ['bezrukov','dyuzhev','maykov','vdovichenkov','guseva','panin','telichkina','eremenko','aprelskiy','aronova','poroshina','florinskaya','kuravlev','strahov','garmash','kravchenko','vysokovskiy','inshakov','alekseev','mahmudov','bezrukov_v','poverennova','sasha_belyi','kos','pchela','fil','olga','kaverin','muha','katya','anya','petr_ilich','suhotskiy','san_sanych','vvedenskiy','karelskiy','farkhad','macheha','amateur','anal','asian','bbw','bdsm','big_ass','big_tits','blonde','blowjob','brunette','creampie','cumshot','ebony','gangbang','hentai','interracial','latina','lesbian','milf','teen','goiyum','deadp47','crazy','cocksuckerberg','dildo','maddyson','zhmil','ezhisarmat','zanuda','vanomas','woodush','timofey92','ilame','keks1c','segal','dread','ns','faker','mobster','dedbaldesh','madenemy','opus_magnum','ko1ay','timofey','ahrinyan','alinarin','vityarakotyara','vladimirzolotoy','giggs','arrowwoods','ozon671games','whitera','oxxxymiron','viktorsd','oxxxy','gonefludd','boulevarddepo','pharaoh','lone','basta','noggano','smokymo','slovetsky','guf','ptaha','pes','kaspijskijgruz','husky','scriptonite','104','kravts','ligalayz','detsl','kasta','vladi','hamil','zmey','remdigga','triagrutrika','blaze','flou','andycartier','ati','kurtki','ldpr','gspd','zamay','booker','rocket','jj','krovostok','noizemc','anacondaz','pornofilmy','2hcompany','krec','umbriaco','chemodan','slavakpss','valery','malbec','ogbuda','jeembo','friendlythug52ngg','khan','johnyboy','gnoiny','purulent','khovansky','galat','yubileyniy','vityasd','st1m','crip','drago','meowizzy','sinigang','sasha_skul','harry','repac','prostol','check','mufasa','mozee','pencil','smit','yarki','zloy','uzi','krip','led','bragin','redoff','vibe','dizel']

def generate_code():
    parts = []
    for i in range(4):
        nick = random.choice(words)
        parts.append(nick)
        if i < 2:
            length = random.randint(4, 8)
            chars = string.ascii_letters + string.digits + string.punctuation
            random_chars = ''.join(random.choice(chars) for _ in range(length))
            parts.append(random_chars)
    return ''.join(parts)

