def calculate_check_digit(gtin):
    '''Given a GTIN (8-14) or SSCC, calculate its appropriate check digit'''
    reverse_gtin = gtin[::-1]
    total = 0
    count = 0
    for char in reverse_gtin:
        digit = int(char)
        if count % 2 == 0:
            digit = digit * 3
        total = total + digit
        count = count + 1
    return 10 - (total % 10)


def combine_gtin_with_check_digit(gtin):
    '''Given a gtin, calculate and append its check digit'''
    return gtin + str(calculate_check_digit(gtin))
