package main

// Run 'go env -w GO111MODULE=off' and 'go get github.com/montanaflynn/stats' to install Golang Statistics package 
// https://pkg.go.dev/github.com/montanaflynn/stats#section-readme
// Download Enron email dataset at:
// https://www.cs.cmu.edu/~enron/

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"github.com/montanaflynn/stats"
)

var stopwords map[string]bool

func buildStopwords() {
	stopwordsList := []string{"a", "about", "above", "above", "across", "after",
		"afterwards", "again", "against", "all", "almost", "alone", "along",
		"already", "also", "although", "always", "am", "among", "amongst", "amoungst",
		"amount", "an", "and", "another", "any", "anyhow", "anyone", "anything", "anyway",
		"anywhere", "are", "around", "as", "at", "back", "be", "became", "because", "become",
		"becomes", "becoming", "been", "before", "beforehand", "behind", "being", "below",
		"beside", "besides", "between", "beyond", "bill", "both", "bottom", "but", "by",
		"call", "can", "cannot", "cant", "co", "con", "could", "couldnt", "cry", "de",
		"describe", "detail", "do", "done", "down", "due", "during", "each", "eg", "eight",
		"either", "eleven", "else", "elsewhere", "empty", "enough", "etc", "even", "ever",
		"every", "everyone", "everything", "everywhere", "except", "few", "fifteen", "fify",
		"fill", "find", "fire", "first", "five", "for", "former", "formerly", "forty", "found",
		"four", "from", "front", "full", "further", "get", "give", "go", "had", "has", "hasnt",
		"have", "he", "hence", "her", "here", "hereafter", "hereby", "herein", "hereupon",
		"hers", "herself", "him", "himself", "his", "how", "however", "hundred", "ie", "if",
		"in", "inc", "indeed", "interest", "into", "is", "it", "its", "itself", "keep", "last",
		"latter", "latterly", "least", "less", "ltd", "made", "many", "may", "me", "meanwhile",
		"might", "mill", "mine", "more", "moreover", "most", "mostly", "move", "much", "must",
		"my", "myself", "name", "namely", "neither", "never", "nevertheless", "next", "nine",
		"no", "nobody", "none", "noone", "nor", "not", "nothing", "now", "nowhere", "of", "off",
		"often", "on", "once", "one", "only", "onto", "or", "other", "others", "otherwise",
		"our", "ours", "ourselves", "out", "over", "own", "part", "per", "perhaps", "please",
		"put", "rather", "re", "same", "see", "seem", "seemed", "seeming", "seems", "serious",
		"several", "she", "should", "show", "side", "since", "sincere", "six", "sixty", "so",
		"some", "somehow", "someone", "something", "sometime", "sometimes", "somewhere",
		"still", "such", "system", "take", "ten", "than", "that", "the", "their", "them",
		"themselves", "then", "thence", "there", "thereafter", "thereby", "therefore",
		"therein", "thereupon", "these", "they", "thickv", "thin", "third", "this", "those",
		"though", "three", "through", "throughout", "thru", "thus", "to", "together", "too",
		"top", "toward", "towards", "twelve", "twenty", "two", "un", "under", "until", "up",
		"upon", "us", "very", "via", "was", "we", "well", "were", "what", "whatever", "when",
		"whence", "whenever", "where", "whereafter", "whereas", "whereby", "wherein",
		"whereupon", "wherever", "whether", "which", "while", "whither", "who", "whoever",
		"whole", "whom", "whose", "why", "will", "with", "within", "without", "would", "yet",
		"you", "your", "yours", "yourself", "yourselves", "the"}

	stopwords = make(map[string]bool)
	for _, item := range stopwordsList {
		stopwords[item] = true
	}
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func removeDuplicateInt(intSlice []int) []int {
	keys := make(map[int]bool)
	list := []int{}

	// If the key(values of the slice) is not equal
	// to the already present value in new slice (list)
	// then we append it. else we jump on another element.
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func main() {
	root := "./maildir/"
	senderFolders, _ := ioutil.ReadDir(root)

	if _, err := os.Stat("database"); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir("database", os.ModePerm)
		if err != nil {
			log.Println(err)
		}
	}

	fmt.Println("#Users: ", len(senderFolders))

	buildStopwords()

	userID := 0
	numKeywords := []float64{}

	for _, folder := range senderFolders[0:] {
		userID += 1
		numDocs := 0
		fmt.Println(folder.Name())
		senderSubFolders, _ := ioutil.ReadDir(root + folder.Name() + "/")

		keywordFilePairs := make(map[string][]int)

		fileID := 0

		for _, subFolder := range senderSubFolders[1:] {
			files, _ := ioutil.ReadDir(root + folder.Name() + "/" + subFolder.Name() + "/")
			numDocs = numDocs + len(files)

			for _, file := range files {
				filePath := root + folder.Name() + "/" + subFolder.Name() + "/" + file.Name()
				f, err := os.Open(filePath)
				fileID += 1
				if err != nil {
					fmt.Println(err)
					f.Close()
					return
				}

				scanner := bufio.NewScanner(f)
				scanner.Split(bufio.ScanWords)

				for scanner.Scan() {
					w := strings.ToLower(scanner.Text())
					if len(w) < 4 || len(w) > 20 || stopwords[w] { // remove stopwords and words that are > 20 or < 4 characters long
						continue
					} else { // remove words contaning non-alphabetic characters
						b := true
						for _, c := range w {
							if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
								b = false
								break
							}
						}
						if b {
							keywordFilePairs[w] = append(keywordFilePairs[w], fileID)
						}
					}
				}
				f.Close()
			}
		}

		file, errs := os.Create("database/" + strconv.Itoa(userID) + ".txt")
		if errs != nil {
			fmt.Println("Failed to create file:", errs)
			return
		}

		numKeywords = append(numKeywords, float64(len(keywordFilePairs)))

		for kw, fileIDs := range keywordFilePairs {
			fileIDs = removeDuplicateInt(fileIDs)
			fmt.Fprintf(file, "%s ", kw)
			for _, fileID := range fileIDs {
				fmt.Fprintf(file, "%d ", fileID)
			}
			fmt.Fprintln(file)
		}

		file.Close()
	}
	
	// Print out some statistics information about dataset
	// fmt.Println("Total number of users: ", len(numKeywords))
	fmt.Println("Keywords Statistics: ")
	mean, _ := stats.Mean(numKeywords)
	fmt.Println("Mean: ", mean)
	std, _ := stats.StandardDeviation(numKeywords)
	fmt.Println("Std: ", std)
	min, _ := stats.Min(numKeywords)
	fmt.Println("Min: ", min)
	max, _ := stats.Max(numKeywords)
	fmt.Println("Max: ", max)
}
