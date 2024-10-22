import bcrypt 
import nltk
import time
from nltk.corpus import words
nltk.download('words')
import multiprocessing
stop_event = multiprocessing.Event()

def main():
    passwords = ["Bilbo:$2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq",
    "Gandalf:$2b$08$J9FW66ZdPI2nrIMcOxFYI.q2PW6mqALUl2/uFvV9OFNPmHGNPa6YC",
    "Thorin:$2b$08$J9FW66ZdPI2nrIMcOxFYI.6B7jUcPdnqJz4tIUwKBu8lNMs5NdT9q",
    "Fili:$2b$09$M9xNRFBDn0pUkPKIVCSBzuwNDDNTMWlvn7lezPr8IwVUsJbys3YZm",
    "Kili:$2b$09$M9xNRFBDn0pUkPKIVCSBzuPD2bsU1q8yZPlgSdQXIBILSMCbdE4Im",
    "Balin:$2b$10$xGKjb94iwmlth954hEaw3O3YmtDO/mEFLIO0a0xLK1vL79LA73Gom",
    "Dwalin:$2b$10$xGKjb94iwmlth954hEaw3OFxNMF64erUqDNj6TMMKVDcsETsKK5be",
    "Oin:$2b$10$xGKjb94iwmlth954hEaw3OcXR2H2PRHCgo98mjS11UIrVZLKxyABK",
    "Gloin:$2b$11$/8UByex2ktrWATZOBLZ0DuAXTQl4mWX1hfSjliCvFfGH7w1tX5/3q",
    "Dori:$2b$11$/8UByex2ktrWATZOBLZ0Dub5AmZeqtn7kv/3NCWBrDaRCFahGYyiq",
    "Nori:$2b$11$/8UByex2ktrWATZOBLZ0DuER3Ee1GdP6f30TVIXoEhvhQDwghaU12",
    "Ori:$2b$12$rMeWZtAVcGHLEiDNeKCz8OiERmh0dh8AiNcf7ON3O3P0GWTABKh0O",
    "Bifur:$2b$12$rMeWZtAVcGHLEiDNeKCz8OMoFL0k33O8Lcq33f6AznAZ/cL1LAOyK",
    "Bofur:$2b$12$rMeWZtAVcGHLEiDNeKCz8Ose2KNe821.l2h5eLffzWoP01DlQb72O",
    "Durin$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay"]

    # password 1: welcome, Time: 406.2778642177582 seconds
    # password 2: [('wizard', 358.1613562107086)]
    # password 3: [('diamond', 314.277658700943)]
    # password 4: [('desire', 615.3194708824158)]
    # password 5: [('ossify', 405.06106328964233)]
    # password 6: [('hangout', 1387.1523876190186)]
    # password 7: [('drossy', 68.48036813735962)]
    # password 8: [('ispaghul', 600.1843917369843)]
    # password 9: [('oversave', 1893.5889875888824)]
    # password 10: [('indoxylic', 823.2115032672882]
    # passwoed 11: [('swagsman', 1815.8683257102966)]
    # password 12: [('airway', 925.1476845741272)]
    # password 13: [('corrosible', 3188.5273220539093)]
    # password 14: [('libellate', 4050.8400366306305)] 
    # passwoed 15: [('purrone', 4519.37490105629)]

    word_list = words.words()
    filtered_words = [word for word in word_list if 6 <= len(word) <= 10]

    cracked_list = []

    if __name__ == "__main__":
        num_processes = multiprocessing.cpu_count()
        chunk_size = len(filtered_words) // num_processes  
        chunks = list(divide_list(filtered_words, chunk_size))

       # stop_event = multiprocessing.Event()

        #process(chunks, passwords[0])
    #print("formatted", format_inputs(passwords[2:]))
        formatted = format_inputs(passwords[2:])

        for password in formatted:
            with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
                #results = pool.starmap(crack_pw, (filtered_words, passwords[0]))
                results = pool.starmap(crack_pw, [(chunk, passwords) for chunk in chunks])
                print("results", results)
                cracked_list.append(parse_results(results))
            # print("iteration:", cracked_list)
        print("Final:", cracked_list)
    return

def format_inputs(password_list):
    formatted_list = []
    for password in password_list:
        for idx in range(len(password)):
            if password[idx] == ":":
                formatted_list.append((bytes(password[idx + 1: len(password) + 1], 'utf-8')))
    return formatted_list

def crack_pw(word_list, pass_word):
    start_time = time.time()
    for word in word_list:
        #if stop_event.is_set():
        #    return None
        outcome = bcrypt.checkpw(bytes(word, 'utf-8'), pass_word)
        if outcome == True:
            print("True", word)
            elapsed_time = time.time() - start_time
            print("TIme:", elapsed_time)
            #stop_event.set()
            return word, elapsed_time
    return None

def parse_results(result_lst):
    for result in result_lst:
        if result != None:
            word, etime = result
            return word, etime


    # outcome = bcrypt.checkpw(bytes(word, 'utf-8'), pass_word)
    # if outcome == True:
    #     print("True", word)
    #     return word
    # return False

def divide_list(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

    # for word in word_list:
    #     outcome = bcrypt.checkpw(bytes(word, 'utf-8'), pass_word)
    #     if outcome == True:
    #         print("True", word)
    #         return word
    # return False


main()