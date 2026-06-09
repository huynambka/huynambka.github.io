+++
date = '2025-03-20T00:05:00+07:00'
draft = false
title = 'Insecure Deserialization 101'
description = 'When developing a game, you may need to save a player’s run to a file so that you don’t lose their progress and they can return to where they left off.'
tags = ['technical']
+++
# Insecure Deserialization

## Overview

When developing a game, you may need to save a player’s run to a file so that you don’t lose their progress and they can return to where they left off.

Indeed, there are many cases where we want to save the state of our application to restore it in the future. Two terms are used to define this process: **serialization and deserialization.**

### What is deserialization (and serialization)?

Serialization is the process of converting the state of an application into a format suitable for transfer or storage. Deserialization is the reverse process and therefore restores the state of the application.

## Deserialization in PHP

### How it works?

In PHP, the [serialize](https://www.php.net/manual/en/function.serialize.php) function is used to serialize a data structure and its type. The [unserialize](https://www.php.net/manual/en/function.unserialize.php) function is used to go backwards.

After the data is serialized, it is represented differently according to its type.

* For a string `s:13: "Hello, world!";`, the number corresponds to its length.
* For an integer, `i:42;`.
* For a boolean, `b:0; or b:1;`.
* For the value `null, N;`.
* For a list `a:1:{s:5: "hello";s:5: "world";}`, the first number is the number of entries in the list, and between the braces is a sequence of keys/values.
* For an `O:5: "Hello":1:{s:7: "to_whom";s:5: "World";}`, the first number is the length of the class name and the rest is the same as for a list.

### Possible Exploitations

Take the code below for example.

```php
class TemporaryStorage {
	public $files = array();

	function __destruct() {
		foreach ($this->files as $temp_file) {
			echo "Deleting $temp_file...\n";
			@unlink($temp_file);
		}
	}
};

unserialize($_GET["user_data"]);
```

Then pass this to the `unserialize` function.

```
O:16:"TemporaryStorage":1:{s:5:"files";a:2:
{i:0;s:20:"/app/application.php";i:1;s:16:"/data/datbase.db";}}
```

Some libraries containing vulnerable classes can be used, which increases the possibilities for an attacker. On this point, the [phpggc](https://github.com/ambionics/phpggc) project collects a list of classes that can be exploited in frequently used libraries and frameworks.

If another vulnerability is present in your application that allows arbitrary editing of PHP sessions, then an attacker could use it to perform dangerous deserialization because _**sessions are nothing more than serialized objects**_.

### HackTheBox Challenges

There are serveral HackTheBox challenges that you can practice this technique.&#x20;

* (updating ...)

## Deserialization in C# with Json.NET

### How it works?

The Json.NET librabry allows you to serialize and deserialize data in a format that is considered safe: JSON. Unfortunately, when deserializing, the library use the `$type` field in an object to know which class is instantiate.&#x20;

If the `TypeNameHandling.Objects` option is used, then when trying to deserialise an item of type `object` any type can be specified (described [here](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2326)).

### Possible Expolitations

For example, consider the following case:

```csharp
using System.Diagnostics;
using Newtonsoft.Json;

public class CommandManager {
	public string? output { get; set; }

	private string? _command;

	public string? command {
		get { return _command; }

		set {
			_command = value;

			Process p = new Process();
			p.StartInfo.RedirectStandardOutput = true;
			p.StartInfo.FileName = "/usr/bin/env";
			p.StartInfo.Arguments = _command;
			p.Start();

			output = p.StandardOutput.ReadToEnd();
			p.WaitForExit();

			Console.WriteLine(output);
		}
	}
};
```

This class has a custom setter for the `command` field, it will execute the command passed and put the output into the `output` field. As explained above, if we use the Json.NET library to deserialize, then we can specify the name of this structure in the `$type` field and call the `command` setter.

```csharp
var result = JsonConvert.DeserializeObject<object>(
	user_input,
	new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Objects }
);
```

If we use the above code to deserialise the data below:

```json
{"$type":"CommandManager, myproject","command":"id"}
```

Then the `CommandManager` setter will be called and our `id` command executed. In the same way as for PHP exploitation, there are lists of vulnerable classes on projects like [ysoserial.net](https://github.com/pwntester/ysoserial.net).

### HackTheBox Challenges

There are serveral HackTheBox challenges that you can practice this technique.&#x20;

* [Nexus Void](https://app.hackthebox.com/challenges/Nexus%20Void) (writeups)
* (updating ...)

## References

* [Vaadata's Blog](https://www.vaadata.com/blog/exploiting-and-preventing-insecure-deserialization-vulnerabilities/)
